package tacra

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/fxamacker/cbor/v2"
	"github.com/globalsign/est"
)

// The EST server's answers when what stands behind it does not answer: an RRP it cannot reach (502, Bad Gateway) and,
// in the Passport model, a verifier it cannot reach (503, Service Unavailable). Each is a real failure, a TCP port
// that nothing listens on, reached through the TLS clients the server builds from its configuration.

const caFileMode = 0o600 // owner read and write

// closedPort is the address of a local TCP port that nothing listens on.
func closedPort(t *testing.T) string {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := l.Addr().String()
	if err := l.Close(); err != nil {
		t.Fatal(err)
	}
	return addr
}

// caFile writes a self-signed CA certificate, the trust anchor the server's TLS clients are configured with.
func caFile(t *testing.T) string {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "test CA"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), IsCA: true,
		BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "ca.pem")
	if err := os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), caFileMode); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestUnreachable(t *testing.T) {
	ca := caFile(t)
	const target = "https://db-none.tacra.example"
	b, err := New(Config{
		Verifiers: map[string]Verifier{"veraison": {URL: "https://" + closedPort(t), CA: ca, Provider: "sev_guest"}},
		RRPs: map[string]RRP{"ca": {URL: "https://" + closedPort(t), CA: ca, RRPID: "https://ca1.tacra.example",
			Mode: est.MechanismEnroll, Verifiers: []string{"veraison"}}},
		Targets:            map[string]string{target: "ca"},
		AcceptableEvidence: []string{"application/vnd.veraison.tsm-report+cbor"},
	})
	if err != nil {
		t.Fatal(err)
	}
	h, err := est.NewRouter(&est.ServerConfig{CA: b})
	if err != nil {
		t.Fatal(err)
	}

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet,
		"/.well-known/est/attest-initiate?credential_type=x509&target=https%3A%2F%2Fdb-none.tacra.example", nil))
	if got, want := rec.Body.String(), "502 RRP ca unreachable\n"; rec.Code != http.StatusBadGateway || got != want {
		t.Errorf("attest-initiate with the RRP down: %d %q, want %q", rec.Code, got, want)
	}

	// An absent-none Enrollment, which needs no attest-initiate: the server reads the Evidence's TSM provider to choose
	// the verifier (verifierFor), so the Evidence is a TSM report with that field and nothing else.
	evidence, err := cbor.Marshal(map[string]string{"provider": "sev_guest"})
	if err != nil {
		t.Fatal(err)
	}
	body, err := json.Marshal(map[string]any{"target": target, "freshness_kind": est.FreshnessAbsentNone,
		"csr":      base64.RawURLEncoding.EncodeToString([]byte("a CSR the server forwards unopened")),
		"evidence": base64.RawURLEncoding.EncodeToString(evidence),
		"binding":  map[string]string{"method": est.BindingInput, "hash": "sha512"}})
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodPost, "/.well-known/est/attest-enroll", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/est-attest-enroll+json")
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if got, want := rec.Body.String(), "503 verifier unavailable\n"; rec.Code != http.StatusServiceUnavailable || got != want {
		t.Errorf("attest-enroll with the verifier down: %d %q, want %q", rec.Code, got, want)
	}
}
