package tacra

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

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

	evidence := []byte("a TSM report, unopened by the EST server")
	csr := []byte("the CSR's DER")
	for _, model := range []string{"", passport, backgroundCheck} {
		cfg := Config{RRPs: map[string]RRP{"ca1": {URL: rrp.URL, CA: caFile(t, rrp), RRPID: rrpID, Mode: est.MechanismEnroll, RATSModel: model}},
			Targets: map[string]string{target: "ca1"}, AcceptableEvidence: []string{evidenceType}}
		cfg.Veraison.URL, cfg.Veraison.CA = verifier.URL, caFile(t, verifier)
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
	if _, err := New(Config{RRPs: map[string]RRP{"ca1": {URL: rrp.URL, CA: caFile(t, rrp), RRPID: rrpID, Mode: est.MechanismEnroll,
		RATSModel: "both"}}, AcceptableEvidence: []string{evidenceType}, Veraison: struct {
		URL string `json:"url"`
		CA  string `json:"ca"`
	}{verifier.URL, caFile(t, verifier)}}); err == nil {
		t.Error("rats_model \"both\" was accepted")
	}
}
