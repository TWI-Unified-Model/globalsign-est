package est_test

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
	"errors"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/globalsign/est"
)

// The messages of the reference implementation of draft-novak-lamps-tacra-est (tacra-est, Python), as one of its
// runs on GCP SEV-SNP hardware recorded them (evidence/20261001T165956Z-gcp-sev-snp/vectors.json at tacra-est
// 4c0efbc): the envelopes of the draft's CDDL, every bstr as unpadded base64url.
const refVectors = "testdata/tacra-est-ref-vectors-sev-snp.json"

type refVectorFile struct {
	Enrollment struct {
		Initiation json.RawMessage `json:"AttestationInitiationResponse"`
		Request    json.RawMessage `json:"AttestedEnrollmentRequest"`
	} `json:"enrollment"`
	Retrieval struct {
		Initiation json.RawMessage `json:"AttestationInitiationResponse"`
		Request    json.RawMessage `json:"AttestedRetrievalRequest"`
		Bundle     json.RawMessage `json:"EncryptedCredentialBundle"`
	} `json:"retrieval"`
}

func loadRefVectors(t *testing.T) refVectorFile {
	t.Helper()
	raw, err := os.ReadFile(refVectors)
	if err != nil {
		t.Fatal(err)
	}
	var v refVectorFile
	if err := json.Unmarshal(raw, &v); err != nil {
		t.Fatal(err)
	}
	return v
}

func b64u(t *testing.T, s string) []byte {
	t.Helper()
	b, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil {
		t.Fatalf("not unpadded base64url: %q", s[:min(len(s), 20)])
	}
	return b
}

func asMap(t *testing.T, raw []byte) map[string]any {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatal(err)
	}
	return m
}

// decodeStrict decodes as the server does: unknown members refused.
func decodeStrict(raw []byte, v any) error {
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	return d.Decode(v)
}

// TestRefEnvelopesRoundTrip: each message of the reference implementation decodes into this package's types with
// no member unknown, and encodes back to the same JSON, member for member.
func TestRefEnvelopesRoundTrip(t *testing.T) {
	v := loadRefVectors(t)
	for name, c := range map[string]struct {
		raw []byte
		v   any
	}{
		"AttestedEnrollmentRequest":                {v.Enrollment.Request, &est.AttestedEnrollmentRequest{}},
		"AttestedRetrievalRequest":                 {v.Retrieval.Request, &est.AttestedRetrievalRequest{}},
		"AttestationInitiationResponse (enroll)":   {v.Enrollment.Initiation, &est.AttestationInitiateResponse{}},
		"AttestationInitiationResponse (retrieve)": {v.Retrieval.Initiation, &est.AttestationInitiateResponse{}},
	} {
		if err := decodeStrict(c.raw, c.v); err != nil {
			t.Errorf("%s: %v", name, err)
			continue
		}
		again, err := json.Marshal(c.v)
		if err != nil {
			t.Fatal(err)
		}
		if got, want := asMap(t, again), asMap(t, c.raw); !reflect.DeepEqual(got, want) {
			t.Errorf("%s: encodes back to\n%s\nnot\n%s", name, again, c.raw)
		}
	}

	var enr est.AttestedEnrollmentRequest
	_ = json.Unmarshal(v.Enrollment.Request, &enr)
	if _, err := x509.ParseCertificateRequest(enr.CSR); err != nil {
		t.Errorf("the CSR does not parse: %v", err)
	}
	if enr.Binding.Method != "binding-input" || enr.Binding.Hash != "sha512" || len(enr.Handle) != 32 {
		t.Errorf("binding %+v, handle %d octets", enr.Binding, len(enr.Handle))
	}
	var ret est.AttestedRetrievalRequest
	_ = json.Unmarshal(v.Retrieval.Request, &ret)
	if len(ret.CEKPub) != 1249 {
		t.Errorf("cek_pub is %d octets, want the 1249-octet MLKEM768-P256 encapsulation key", len(ret.CEKPub))
	}
}

// TestB64URLCompat: bstr members are written as unpadded base64url and read in either encoding.
func TestB64URLCompat(t *testing.T) {
	octets := []byte{0xfb, 0xff, 0xbf, 0x00, 0x01}
	out, err := json.Marshal(est.AttestedEnrollmentRequest{Handle: octets})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(out), `"handle":"-_-_AAE"`) {
		t.Fatalf("handle written as %s, want unpadded base64url", out)
	}
	for _, enc := range []string{"-_-_AAE", base64.StdEncoding.EncodeToString(octets)} {
		var r est.AttestedEnrollmentRequest
		if err := json.Unmarshal([]byte(`{"handle":"`+enc+`","csr":"","evidence":"","target":"t","freshness_kind":"present-nonce","binding":{"method":"binding-input"}}`), &r); err != nil {
			t.Fatalf("%s: %v", enc, err)
		}
		if !bytes.Equal(r.Handle, octets) {
			t.Fatalf("%s decoded to %x", enc, r.Handle)
		}
	}
}

// refCA is an attesting CA that records what the EST server hands it.
type refCA struct {
	enroll   *est.AttestedEnrollmentRequest
	retrieve *est.AttestedRetrievalRequest
	cert     *x509.Certificate
	bundle   []byte
}

func (c *refCA) CACerts(context.Context, string, *http.Request) ([]*x509.Certificate, error) {
	return []*x509.Certificate{c.cert}, nil
}
func (c *refCA) CSRAttrs(context.Context, string, *http.Request) (est.CSRAttrs, error) {
	return est.CSRAttrs{}, nil
}
func (c *refCA) Enroll(context.Context, *x509.CertificateRequest, string, *http.Request) (*x509.Certificate, error) {
	return nil, errors.New("not used")
}
func (c *refCA) Reenroll(context.Context, *x509.Certificate, *x509.CertificateRequest, string, *http.Request) (*x509.Certificate, error) {
	return nil, errors.New("not used")
}
func (c *refCA) ServerKeyGen(context.Context, *x509.CertificateRequest, string, *http.Request) (*x509.Certificate, []byte, error) {
	return nil, nil, errors.New("not used")
}
func (c *refCA) TPMEnroll(context.Context, *x509.CertificateRequest, []*x509.Certificate, []byte, []byte, string, *http.Request) ([]byte, []byte, []byte, error) {
	return nil, nil, nil, errors.New("not used")
}
func (c *refCA) InitiateRemoteAttestation(context.Context, string, string, string, *http.Request) (*est.AttestationInitiateResponse, error) {
	return &est.AttestationInitiateResponse{FreshnessKind: "present-nonce", Handle: bytes.Repeat([]byte{0xfb}, 32),
		RRPID: "https://ca1.tacra.example", ExpiresIn: 300, Mechanism: "enroll"}, nil
}
func (c *refCA) EnrollCredential(_ context.Context, req *est.AttestedEnrollmentRequest, _ string, _ *http.Request) (*x509.Certificate, error) {
	c.enroll = req
	return c.cert, nil
}
func (c *refCA) RetrieveCredential(context.Context, *est.AttestedRetrievalRequest, string, *http.Request) (*est.EncryptedCredentialBundle, error) {
	return nil, errors.New("RetrieveCredentialRaw serves attest-retrieve")
}
func (c *refCA) RetrieveCredentialRaw(_ context.Context, req *est.AttestedRetrievalRequest, _ string, _ *http.Request) ([]byte, error) {
	c.retrieve = req
	return c.bundle, nil
}

// TestRefRequestsThroughServer: the reference implementation's requests, sent with its media types, reach the
// attesting CA through this server's router unchanged; the Vault's container comes back as it was; the Handle of
// attest-initiate goes out as unpadded base64url.
func TestRefRequestsThroughServer(t *testing.T) {
	v := loadRefVectors(t)
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tpl := &x509.Certificate{SerialNumber: big.NewInt(7), Subject: pkix.Name{CommonName: "workload.tacra.example"},
		NotBefore: time.Now(), NotAfter: time.Now().Add(time.Hour)}
	der, _ := x509.CreateCertificate(rand.Reader, tpl, tpl, &key.PublicKey, key)
	cert, _ := x509.ParseCertificate(der)
	ca := &refCA{cert: cert, bundle: v.Retrieval.Bundle}
	r, err := est.NewRouter(&est.ServerConfig{CA: ca, Timeout: 10 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(r)
	defer srv.Close()

	post := func(path, ctype string, body []byte) (*http.Response, []byte) {
		resp, err := http.Post(srv.URL+"/.well-known/est"+path, ctype, bytes.NewReader(body))
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		b, _ := io.ReadAll(resp.Body)
		return resp, b
	}

	resp, body := post("/attest-enroll", "application/est-attest-enroll+json", v.Enrollment.Request)
	if resp.StatusCode != http.StatusOK || ca.enroll == nil {
		t.Fatalf("attest-enroll: %d %s", resp.StatusCode, body)
	}
	want := asMap(t, v.Enrollment.Request)
	if !bytes.Equal(ca.enroll.CSR, b64u(t, want["csr"].(string))) || !bytes.Equal(ca.enroll.Evidence, b64u(t, want["evidence"].(string))) ||
		!bytes.Equal(ca.enroll.Handle, b64u(t, want["handle"].(string))) || ca.enroll.Target != want["target"] ||
		ca.enroll.Profile != want["profile"] || ca.enroll.CredentialHint == nil || *ca.enroll.CredentialHint != want["credential_hint"] {
		t.Fatal("the CA did not receive the reference implementation's enrollment request as it was sent")
	}

	resp, body = post("/attest-retrieve", "application/est-attest-retrieve+json", v.Retrieval.Request)
	if resp.StatusCode != http.StatusOK || ca.retrieve == nil {
		t.Fatalf("attest-retrieve: %d %s", resp.StatusCode, body)
	}
	wantR := asMap(t, v.Retrieval.Request)
	if !bytes.Equal(ca.retrieve.CEKPub, b64u(t, wantR["cek_pub"].(string))) || !bytes.Equal(ca.retrieve.Evidence, b64u(t, wantR["evidence"].(string))) {
		t.Fatal("the CA did not receive the reference implementation's retrieval request as it was sent")
	}
	if !reflect.DeepEqual(asMap(t, body), asMap(t, v.Retrieval.Bundle)) {
		t.Fatal("the container did not come back as the Vault made it")
	}

	// application/json is still taken; a media type of neither kind is 415
	if resp, _ := post("/attest-enroll", "application/json", v.Enrollment.Request); resp.StatusCode != http.StatusOK {
		t.Fatalf("application/json: %d", resp.StatusCode)
	}
	if resp, _ := post("/attest-enroll", "text/plain", v.Enrollment.Request); resp.StatusCode != http.StatusUnsupportedMediaType {
		t.Fatalf("text/plain: %d", resp.StatusCode)
	}

	gr, err := http.Get(srv.URL + "/.well-known/est/attest-initiate?target=https://db.tacra.example&credential_type=x509")
	if err != nil {
		t.Fatal(err)
	}
	defer gr.Body.Close()
	ib, _ := io.ReadAll(gr.Body)
	if got := asMap(t, ib)["handle"]; got != base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{0xfb}, 32)) {
		t.Fatalf("attest-initiate handle %v, want unpadded base64url", got)
	}
}
