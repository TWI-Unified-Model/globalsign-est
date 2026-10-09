package tacra

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/fxamacker/cbor/v2"
	"github.com/globalsign/est"
)

// fakes records what the backend sends to the verifier and to the RRP.
type fakes struct {
	mu        sync.Mutex
	verifier  []string // nonces of the sessions opened at the verifier (base64url)
	enrollLeg []map[string]any
}

func caFile(t *testing.T, srv *httptest.Server) string {
	p := filepath.Join(t.TempDir(), "ca.pem")
	if err := os.WriteFile(p, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srv.Certificate().Raw}), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

// TestRATSModels: for an RRP in the Passport model the backend opens the verifier session, with the binding value
// as its nonce, and forwards the Attestation Results; for an RRP in the Background Check model it never asks the
// verifier and forwards the Evidence and its media type. The Attester's messages are the same in both.
func TestRATSModels(t *testing.T) {
	const target, rrpID, evidenceType = "https://db.tacra.example", "https://ca1.tacra.example", "application/vnd.veraison.tsm-report+cbor"
	f := &fakes{}
	verifier := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodPost && r.URL.Path == "/challenge-response/v1/newSession":
			f.mu.Lock()
			f.verifier = append(f.verifier, r.URL.Query().Get("nonce"))
			f.mu.Unlock()
			w.Header().Set("Location", "session/1")
			w.WriteHeader(http.StatusCreated)
		case r.Method == http.MethodPost:
			_ = json.NewEncoder(w).Encode(map[string]string{"status": "complete", "result": "header.claims.signature"})
		default:
			w.WriteHeader(http.StatusNoContent)
		}
	}))
	defer verifier.Close()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	der, _ := x509.CreateCertificate(rand.Reader, &x509.Certificate{SerialNumber: big.NewInt(1),
		Subject: pkix.Name{CommonName: "workload.tacra.example"}, NotBefore: time.Now(), NotAfter: time.Now().Add(time.Hour)},
		&x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "test CA"}}, &key.PublicKey, key)
	handle := bytes.Repeat([]byte{0x42}, 32)
	rrp := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		switch r.URL.Path {
		case "/tacra/v1/initiate":
			_ = json.NewEncoder(w).Encode(map[string]any{"freshness_kind": est.FreshnessPresentNonce, "handle": b64u(handle),
				"rrp_id": rrpID, "expires_in": 300, "mode": est.MechanismEnroll})
		case "/tacra/v1/enroll":
			var leg map[string]any
			_ = json.Unmarshal(body, &leg)
			f.mu.Lock()
			f.enrollLeg = append(f.enrollLeg, leg)
			f.mu.Unlock()
			_ = json.NewEncoder(w).Encode(map[string]any{"certificate_chain": []string{b64u(der)}})
		}
	}))
	defer rrp.Close()

	evidence := tsmReport(t, "sev_guest")
	csr := []byte("the CSR's DER")
	for _, model := range []string{"", passport, backgroundCheck} {
		cfg := Config{RRPs: map[string]RRP{"ca1": {URL: rrp.URL, CA: caFile(t, rrp), RRPID: rrpID, Mode: est.MechanismEnroll,
			RATSModel: model, Verifiers: []string{"veraison"}}},
			Verifiers: map[string]Verifier{"veraison": {URL: verifier.URL, CA: caFile(t, verifier), Provider: "sev_guest"}},
			Targets:   map[string]string{target: "ca1"}, AcceptableEvidence: []string{evidenceType}}
		b, err := New(cfg)
		if err != nil {
			t.Fatal(err)
		}
		f.verifier, f.enrollLeg = nil, nil
		init, err := b.InitiateRemoteAttestation(context.Background(), target, "x509", "", nil)
		if err != nil || !bytes.Equal(init.Handle, handle) {
			t.Fatalf("%q: initiate: %v", model, err)
		}
		if _, err := b.EnrollCredential(context.Background(), &est.AttestedEnrollmentRequest{Target: target, CredentialType: "x509",
			FreshnessKind: est.FreshnessPresentNonce, Handle: handle, CSR: csr, Evidence: evidence, Profile: evidenceType}, "", nil); err != nil {
			t.Fatalf("%q: enroll: %v", model, err)
		}
		if len(f.enrollLeg) != 1 {
			t.Fatalf("%q: the RRP received %d second legs", model, len(f.enrollLeg))
		}
		leg := f.enrollLeg[0]
		if model == backgroundCheck {
			if len(f.verifier) != 0 {
				t.Errorf("background-check: the EST server opened %d verifier sessions; it must open none", len(f.verifier))
			}
			if leg["evidence"] != b64u(evidence) || leg["profile"] != evidenceType || leg["ear"] != nil {
				t.Errorf("background-check: the RRP received %v; want the Evidence and its media type, no EAR", leg)
			}
			continue
		}
		bv := bindingValue(handle, target, rrpID, csr)
		if len(f.verifier) != 1 || f.verifier[0] != base64.URLEncoding.EncodeToString(bv) {
			t.Errorf("%q: verifier sessions %v, want one with the binding value", model, f.verifier)
		}
		if leg["ear"] != "header.claims.signature" || leg["evidence"] != nil {
			t.Errorf("%q: the RRP received %v; want the Attestation Results, no Evidence", model, leg)
		}
	}
	verifiers := map[string]Verifier{"veraison": {URL: verifier.URL, CA: caFile(t, verifier), Provider: "sev_guest"}}
	if _, err := New(Config{RRPs: map[string]RRP{"ca1": {URL: rrp.URL, CA: caFile(t, rrp), RRPID: rrpID, Mode: est.MechanismEnroll,
		RATSModel: "both", Verifiers: []string{"veraison"}}}, AcceptableEvidence: []string{evidenceType}, Verifiers: verifiers}); err == nil {
		t.Error("rats_model \"both\" was accepted")
	}
	if _, err := New(Config{RRPs: map[string]RRP{"ca1": {URL: rrp.URL, CA: caFile(t, rrp), RRPID: rrpID, Mode: est.MechanismEnroll}},
		AcceptableEvidence: []string{evidenceType}, Verifiers: verifiers}); err == nil {
		t.Error("a Passport RRP that names no verifier was accepted")
	}
	if _, err := New(Config{RRPs: map[string]RRP{"ca1": {URL: rrp.URL, CA: caFile(t, rrp), RRPID: rrpID, Mode: est.MechanismEnroll,
		Verifiers: []string{"chosen-by-evidence"}}}, AcceptableEvidence: []string{evidenceType}, Verifiers: verifiers}); err == nil {
		t.Error("an RRP that names an unknown verifier was accepted")
	}
}

func tsmReport(t *testing.T, provider string) []byte {
	b, err := cbor.Marshal(map[string]any{"provider": provider, "outblob": bytes.Repeat([]byte{7}, 64)})
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// TestVerifierFromRRPPolicy (N24): in Passport this server asks only the verifiers the RRP takes, the one for the
// Evidence's TSM provider, and refuses Evidence none of them appraises before asking any verifier.
func TestVerifierFromRRPPolicy(t *testing.T) {
	const target, rrpID, evidenceType = "https://db.tacra.example", "https://ca1.tacra.example", "application/vnd.veraison.tsm-report+cbor"
	var mu sync.Mutex
	asked := map[string]int{}
	fakeVerifier := func(name string) *httptest.Server {
		return httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path == "/challenge-response/v1/newSession" {
				mu.Lock()
				asked[name]++
				mu.Unlock()
				w.Header().Set("Location", "session/1")
				w.WriteHeader(http.StatusCreated)
				return
			}
			_ = json.NewEncoder(w).Encode(map[string]string{"status": "complete", "result": "h.c.s"})
		}))
	}
	veraison, tdx := fakeVerifier("veraison"), fakeVerifier("tdx")
	defer veraison.Close()
	defer tdx.Close()
	handle := bytes.Repeat([]byte{0x42}, 32)
	rrp := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/tacra/v1/initiate":
			_ = json.NewEncoder(w).Encode(map[string]any{"freshness_kind": est.FreshnessPresentNonce, "handle": b64u(handle),
				"rrp_id": rrpID, "expires_in": 300, "mode": est.MechanismEnroll})
		default:
			w.WriteHeader(http.StatusForbidden)
		}
	}))
	defer rrp.Close()
	verifiers := map[string]Verifier{"veraison": {URL: veraison.URL, CA: caFile(t, veraison), Provider: "sev_guest"},
		"tdx": {URL: tdx.URL, CA: caFile(t, tdx), Provider: "tdx_guest"}}
	enroll := func(takes []string, provider string) error {
		b, err := New(Config{Verifiers: verifiers, Targets: map[string]string{target: "ca1"}, AcceptableEvidence: []string{evidenceType},
			RRPs: map[string]RRP{"ca1": {URL: rrp.URL, CA: caFile(t, rrp), RRPID: rrpID, Mode: est.MechanismEnroll, Verifiers: takes}}})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := b.InitiateRemoteAttestation(context.Background(), target, "x509", "", nil); err != nil {
			t.Fatal(err)
		}
		_, err = b.EnrollCredential(context.Background(), &est.AttestedEnrollmentRequest{Target: target, CredentialType: "x509",
			FreshnessKind: est.FreshnessPresentNonce, Handle: handle, CSR: []byte("csr"), Evidence: tsmReport(t, provider),
			Profile: evidenceType}, "", nil)
		return err
	}
	status := func(err error) int {
		var h *httpError
		if errors.As(err, &h) {
			return h.status
		}
		return 0
	}
	// the RRP takes both: tdx_guest Evidence goes to the TDX verifier alone (the fake RRP then refuses: 403 from it)
	_ = enroll([]string{"veraison", "tdx"}, "tdx_guest")
	if asked["tdx"] != 1 || asked["veraison"] != 0 {
		t.Errorf("tdx_guest Evidence, an RRP that takes both: asked %v, want the TDX verifier once", asked)
	}
	// the RRP takes Veraison alone: tdx_guest Evidence, or Evidence of no or another provider, is refused, no one asked
	for _, provider := range []string{"tdx_guest", "", "made_up_guest"} {
		before := asked["tdx"] + asked["veraison"]
		err := enroll([]string{"veraison"}, provider)
		if status(err) != http.StatusForbidden || asked["tdx"]+asked["veraison"] != before {
			t.Errorf("provider %q, an RRP that takes Veraison alone: %v (status %d), %d verifiers asked; want 403, none asked",
				provider, err, status(err), asked["tdx"]+asked["veraison"]-before)
		}
	}
}

// TestMutualTLS (N23): this server presents its client certificate to an RRP that requires one, and cannot reach it
// without.
func TestMutualTLS(t *testing.T) {
	caKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	caTpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "infra"}, IsCA: true,
		BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign, NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(time.Hour)}
	caDER, _ := x509.CreateCertificate(rand.Reader, caTpl, caTpl, &caKey.PublicKey, caKey)
	caCert, _ := x509.ParseCertificate(caDER)
	clientKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	clientDER, _ := x509.CreateCertificate(rand.Reader, &x509.Certificate{SerialNumber: big.NewInt(2),
		Subject: pkix.Name{CommonName: "est-server"}, DNSNames: []string{"est-server.bench.tacra.example"},
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}, KeyUsage: x509.KeyUsageDigitalSignature,
		NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(time.Hour)}, caCert, &clientKey.PublicKey, caKey)
	dir := t.TempDir()
	certPath, keyPath := filepath.Join(dir, "est-server.crt"), filepath.Join(dir, "est-server.key")
	kd, _ := x509.MarshalECPrivateKey(clientKey)
	_ = os.WriteFile(certPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: clientDER}), 0o600)
	_ = os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: kd}), 0o600)
	pool := x509.NewCertPool()
	pool.AddCert(caCert)
	var callers []string
	rrp := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		callers = append(callers, r.TLS.PeerCertificates[0].DNSNames...)
		_ = json.NewEncoder(w).Encode(map[string]any{"freshness_kind": est.FreshnessAbsentNone, "rrp_id": "https://ca1.tacra.example",
			"mode": est.MechanismEnroll})
	}))
	rrp.TLS = &tls.Config{ClientAuth: tls.RequireAndVerifyClientCert, ClientCAs: pool, MinVersion: tls.VersionTLS13}
	rrp.StartTLS()
	defer rrp.Close()
	cfg := func(cert, key string) Config {
		return Config{ClientCert: cert, ClientKey: key, Targets: map[string]string{"https://db.tacra.example": "ca1"},
			AcceptableEvidence: []string{"application/vnd.veraison.tsm-report+cbor"},
			RRPs: map[string]RRP{"ca1": {URL: rrp.URL, CA: caFile(t, rrp), RRPID: "https://ca1.tacra.example", Mode: est.MechanismEnroll,
				RATSModel: backgroundCheck}}}
	}
	with, err := New(cfg(certPath, keyPath))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := with.InitiateRemoteAttestation(context.Background(), "https://db.tacra.example", "x509", "", nil); err != nil {
		t.Fatalf("with its client certificate: %v", err)
	}
	if len(callers) != 1 || callers[0] != "est-server.bench.tacra.example" {
		t.Fatalf("the RRP saw callers %v", callers)
	}
	without, _ := New(cfg("", ""))
	if _, err := without.InitiateRemoteAttestation(context.Background(), "https://db.tacra.example", "x509", "", nil); err == nil {
		t.Fatal("without a client certificate the RRP was reached")
	}
	if _, err := New(cfg(certPath, "")); err == nil {
		t.Fatal("a client certificate without its key was accepted")
	}
}
