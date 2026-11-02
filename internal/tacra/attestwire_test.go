package tacra

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
)

// The attest-enroll and attest-retrieve requests as the EST server takes them, on its own router and this backend: the
// resource's own media type only, and the syntax of the CDDL of the wire format proposed for
// draft-novak-lamps-tacra-est only (attested-enrollment-request, attested-retrieval-request). The backend serves no
// Target, so a request the server takes reaches it and is refused there, 403 "unsupported Target": a 403 shows that
// the media type and the syntax were taken. The requests are real, the reference implementation's from a GCP SEV-SNP
// run (../refvectors/testdata), each also altered.

// refRequest is a request of the reference vectors, by its section ("enrollment", "enrollment_absent_timestamp",
// "retrieval") and name, as compact JSON.
func refRequest(t *testing.T, section, name string) []byte {
	t.Helper()
	raw, err := os.ReadFile("../refvectors/testdata/tacra-est-ref-vectors-sev-snp.json")
	if err != nil {
		t.Fatal(err)
	}
	var file, sec map[string]json.RawMessage
	if err := json.Unmarshal(raw, &file); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(file[section], &sec); err != nil {
		t.Fatalf("the reference %s: %v", section, err)
	}
	var out bytes.Buffer
	if err := json.Compact(&out, sec[name]); err != nil || out.Len() == 0 {
		t.Fatalf("the reference %s %s: %v", section, name, err)
	}
	return out.Bytes()
}

func post(h http.Handler, path, ctype string, body []byte) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodPost, path, bytes.NewReader(body))
	if ctype != "" {
		req.Header.Set("Content-Type", ctype)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

const unsupportedTarget = "404 Target not served\n"

func TestAttestMediaTypes(t *testing.T) {
	h := router(t, nil)
	enroll := refRequest(t, "enrollment", "AttestedEnrollmentRequest")
	retrieve := refRequest(t, "retrieval", "AttestedRetrievalRequest")
	for _, r := range []struct {
		resource, own, other string
		body                 []byte
	}{
		{"attest-enroll", "application/est-attest-enroll+json", "application/est-attest-retrieve+json", enroll},
		{"attest-retrieve", "application/est-attest-retrieve+json", "application/est-attest-enroll+json", retrieve},
	} {
		for _, path := range []string{"/.well-known/est/" + r.resource, "/.well-known/est/arbitraryLabel1/" + r.resource} {
			for _, c := range []struct {
				ctype string
				taken bool
			}{
				{r.own, true},
				{strings.ToUpper(r.own), true}, // type and subtype are case-insensitive (RFC 9110, Section 8.3.1)
				{r.own + "; charset=utf-8", true},
				{"application/json", false},
				{r.other, false},
				{"text/plain", false},
				{r.own + "x", false}, // a type that begins with the resource's
				{"", false},
			} {
				got := post(h, path, c.ctype, r.body)
				if c.taken {
					if got.Code != http.StatusNotFound || got.Body.String() != unsupportedTarget {
						t.Errorf("%s as %q: %d %q, want the backend's %q", path, c.ctype, got.Code, got.Body.String(),
							unsupportedTarget)
					}
					continue
				}
				want := "415 Content-Type must be " + r.own + "\n"
				if got.Code != http.StatusUnsupportedMediaType || got.Body.String() != want ||
					got.Header().Get("Accept") != r.own {
					t.Errorf("%s as %q: %d %q, Accept %q; want 415 %q, Accept %q", path, c.ctype, got.Code,
						got.Body.String(), got.Header().Get("Accept"), want, r.own)
				}
			}
		}
	}
}

// alter returns the JSON object body with the members of set set to their values (a nil value removes the member).
func alter(t *testing.T, body []byte, set map[string]any) []byte {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal(body, &m); err != nil {
		t.Fatal(err)
	}
	for k, v := range set {
		if v == nil {
			delete(m, k)
		} else {
			m[k] = v
		}
	}
	out, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	return out
}

// member is the value of a text member of the JSON object body.
func member(t *testing.T, body []byte, name string) string {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal(body, &m); err != nil {
		t.Fatal(err)
	}
	s, _ := m[name].(string)
	return s
}

func TestAttestRequestSyntax(t *testing.T) {
	h := router(t, nil)
	enroll := refRequest(t, "enrollment", "AttestedEnrollmentRequest")
	timestamp := refRequest(t, "enrollment_absent_timestamp", "AttestedEnrollmentRequest")
	retrieve := refRequest(t, "retrieval", "AttestedRetrievalRequest")
	handle := member(t, enroll, "handle") // 43 characters for 32 octets: the last one carries 2 bits that encode none
	const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
	unusedBitSet := handle[:42] + string(alphabet[strings.IndexByte(alphabet, handle[42])|1])
	evidence := member(t, enroll, "evidence")
	const (
		enrollType   = "application/est-attest-enroll+json"
		retrieveType = "application/est-attest-retrieve+json"
	)
	cases := []struct {
		name, path, ctype string
		body              []byte
		want              string // the server's answer: the backend's 403 when the request was taken
	}{
		{"an enrollment as sent", "attest-enroll", enrollType, enroll, unsupportedTarget},
		{"an absent-timestamp enrollment as sent", "attest-enroll", enrollType, timestamp, unsupportedTarget},
		{"a retrieval as sent", "attest-retrieve", retrieveType, retrieve, unsupportedTarget},
		{"white space after the object", "attest-enroll", enrollType, append(append([]byte{}, enroll...), " \r\n\t"...),
			unsupportedTarget},
		{"an empty object after it", "attest-enroll", enrollType, append(append([]byte{}, enroll...), "{}"...),
			"400 malformed request: data after the JSON object\n"},
		{"the request twice", "attest-enroll", enrollType, bytes.Repeat(enroll, 2),
			"400 malformed request: data after the JSON object\n"},
		{"a member the CDDL does not define (endorsements)", "attest-enroll", enrollType,
			alter(t, enroll, map[string]any{"endorsements": "AAAA"}),
			"400 malformed request: member \"endorsements\" is not defined\n"},
		{"a member name in another case", "attest-enroll", enrollType,
			alter(t, enroll, map[string]any{"target": nil, "Target": member(t, enroll, "target")}),
			"400 malformed request: member \"Target\" is not defined\n"},
		{"a member twice", "attest-enroll", enrollType,
			append([]byte(`{"target":"https://other.tacra.example",`), enroll[1:]...),
			"400 malformed request: member \"target\" appears more than once\n"},
		{"the subject member of the other resource", "attest-enroll", enrollType,
			alter(t, enroll, map[string]any{"csr": nil, "cek_pub": member(t, retrieve, "cek_pub")}),
			"400 malformed request: member \"cek_pub\" is not defined\n"},
		{"null for a member", "attest-enroll", enrollType,
			alter(t, enroll, map[string]any{"credential_hint": json.RawMessage("null")}),
			"400 malformed request: member \"credential_hint\" is not a text string\n"},
		{"a number for a byte string", "attest-enroll", enrollType, alter(t, enroll, map[string]any{"evidence": 1}),
			"400 malformed request: member \"evidence\" is not a text string\n"},
		{"standard base64 for a byte string", "attest-enroll", enrollType,
			alter(t, enroll, map[string]any{"evidence": evidence[:len(evidence)-2] + "+/"}),
			"400 malformed request: member \"evidence\" is not unpadded base64url (RFC 4648, Section 5)\n"},
		{"padding", "attest-enroll", enrollType, alter(t, enroll, map[string]any{"handle": handle + "="}),
			"400 malformed request: member \"handle\" is not unpadded base64url (RFC 4648, Section 5)\n"},
		{"a line break in a byte string", "attest-enroll", enrollType,
			alter(t, enroll, map[string]any{"handle": handle[:20] + "\n" + handle[20:]}),
			"400 malformed request: member \"handle\" is not unpadded base64url (RFC 4648, Section 5)\n"},
		{"a bit that encodes no octet set", "attest-enroll", enrollType,
			alter(t, enroll, map[string]any{"handle": unusedBitSet}),
			"400 malformed request: member \"handle\" is not unpadded base64url (RFC 4648, Section 5)\n"},
		{"no target", "attest-enroll", enrollType, alter(t, enroll, map[string]any{"target": nil}),
			"400 malformed request: no member \"target\"\n"},
		{"no credential_type, which is optional", "attest-retrieve", retrieveType,
			alter(t, retrieve, map[string]any{"credential_type": nil}), unsupportedTarget},
		{"no binding", "attest-enroll", enrollType, alter(t, enroll, map[string]any{"binding": nil}),
			"400 malformed request: no member \"binding\"\n"},
		{"no csr", "attest-enroll", enrollType, alter(t, enroll, map[string]any{"csr": nil}),
			"400 malformed request: no member \"csr\"\n"},
		{"no cek_pub", "attest-retrieve", retrieveType, alter(t, retrieve, map[string]any{"cek_pub": nil}),
			"400 malformed request: no member \"cek_pub\"\n"},
		{"a binding that is not an object", "attest-enroll", enrollType,
			alter(t, enroll, map[string]any{"binding": "binding-input"}),
			"400 malformed request: member \"binding\" is not an object\n"},
		{"a binding without its method", "attest-enroll", enrollType,
			alter(t, enroll, map[string]any{"binding": map[string]any{"hash": "sha512"}}),
			"400 malformed request: no member \"binding.method\"\n"},
		{"a binding with a member the CDDL does not define", "attest-retrieve", retrieveType,
			alter(t, retrieve, map[string]any{"binding": map[string]any{"method": "binding-input", "hash": "sha512", "x": "y"}}),
			"400 malformed request: member \"binding.x\" is not defined\n"},
		{"a Freshness Kind that is not one", "attest-enroll", enrollType,
			alter(t, enroll, map[string]any{"freshness_kind": "present-later"}),
			"400 malformed request: freshness_kind \"present-later\" is not a Freshness Kind\n"},
		{"absent-none with a handle", "attest-enroll", enrollType,
			alter(t, enroll, map[string]any{"freshness_kind": "absent-none"}),
			"400 malformed request: a handle with absent-none\n"},
		{"absent-none without one", "attest-enroll", enrollType,
			alter(t, enroll, map[string]any{"freshness_kind": "absent-none", "handle": nil}), unsupportedTarget},
		{"present-nonce without a handle", "attest-retrieve", retrieveType,
			alter(t, retrieve, map[string]any{"handle": nil}), "400 malformed request: no handle with present-nonce\n"},
		{"absent-timestamp without its handle", "attest-enroll", enrollType,
			alter(t, timestamp, map[string]any{"handle": nil}), "400 malformed request: no handle with absent-timestamp\n"},
		{"an array", "attest-enroll", enrollType, append(append([]byte("["), enroll...), ']'),
			"400 malformed request: the body is not a JSON object\n"},
		{"no body", "attest-enroll", enrollType, nil, "400 malformed request: the body is not a JSON object\n"},
		{"cut short", "attest-enroll", enrollType, enroll[:len(enroll)/2], "400 malformed JSON request body\n"},
		{"invalid UTF-8", "attest-enroll", enrollType,
			bytes.Replace(enroll, []byte(`"credential_hint":"`), []byte("\"credential_hint\":\"\xff"), 1),
			"400 malformed request: the body is not UTF-8 (RFC 8259, Section 8.1)\n"},
		{"over the size limit", "attest-enroll", enrollType, append(bytes.Repeat([]byte(" "), 65536), enroll...),
			"413 request body over the limit of 65536 octets\n"},
	}
	for _, c := range cases {
		for _, path := range []string{"/.well-known/est/" + c.path, "/.well-known/est/arbitraryLabel1/" + c.path} {
			if got := post(h, path, c.ctype, c.body); got.Body.String() != c.want {
				t.Errorf("%s, %s: %d %q, want %q", c.name, path, got.Code, got.Body.String(), c.want)
			}
		}
	}
}
