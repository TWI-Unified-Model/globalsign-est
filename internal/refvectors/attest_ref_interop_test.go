package refvectors_test

import (
	"bytes"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"os"
	"reflect"
	"strings"
	"testing"

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

// withoutRRPID is an attest-initiate response of the reference implementation without its rrp_id, which the wire no
// longer carries: the Attester binds the identifier it holds for the Target and mode, never one from the CAS.
func withoutRRPID(t *testing.T, raw []byte) []byte {
	t.Helper()
	var m map[string]json.RawMessage
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatal(err)
	}
	if _, ok := m["rrp_id"]; !ok {
		t.Fatalf("the reference response has no rrp_id: %s", raw)
	}
	delete(m, "rrp_id")
	out, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	return out
}

// TestRefEnvelopesRoundTrip: each message of the reference implementation decodes into this package's types with
// no member unknown, and encodes back to the same JSON, member for member; its attest-initiate responses once rrp_id,
// which they still carry, is taken out.
func TestRefEnvelopesRoundTrip(t *testing.T) {
	v := loadRefVectors(t)
	for name, c := range map[string]struct {
		raw []byte
		v   any
	}{
		"AttestedEnrollmentRequest":                {v.Enrollment.Request, &est.AttestedEnrollmentRequest{}},
		"AttestedRetrievalRequest":                 {v.Retrieval.Request, &est.AttestedRetrievalRequest{}},
		"AttestationInitiationResponse (enroll)":   {withoutRRPID(t, v.Enrollment.Initiation), &est.AttestationInitiateResponse{}},
		"AttestationInitiationResponse (retrieve)": {withoutRRPID(t, v.Retrieval.Initiation), &est.AttestationInitiateResponse{}},
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

// TestB64URLStrict: byte strings are written as unpadded base64url, and read only as the CDDL's .b64u takes them (RFC
// 9741, Section 2.1): not in standard base64, not padded, not with a line break, not with a bit set that encodes no
// octet.
func TestB64URLStrict(t *testing.T) {
	octets := []byte{0xfb, 0xff, 0xbf, 0x00, 0x01}
	out, err := json.Marshal(est.AttestedEnrollmentRequest{Handle: octets})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(out), `"handle":"-_-_AAE"`) {
		t.Fatalf("handle written as %s, want unpadded base64url", out)
	}
	for enc, ok := range map[string]bool{
		"-_-_AAE": true,
		base64.StdEncoding.EncodeToString(octets): false, // +/+/AAE=
		"-_-_AAE=":  false,
		"-_-_\nAAE": false, // Go's base64 decoder alone takes it
		"-_-_AAF":   false, // F: the two bits after the last octet are 01
	} {
		var b est.B64URL
		err := json.Unmarshal([]byte(`"`+enc+`"`), &b)
		if ok && (err != nil || !bytes.Equal(b, octets)) {
			t.Errorf("%s: %x, %v; want %x", enc, []byte(b), err, octets)
		}
		if !ok && err == nil {
			t.Errorf("%s: decoded to %x, want a refusal", enc, []byte(b))
		}
	}
}
