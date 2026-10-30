package tacra

import (
	"bufio"
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/globalsign/est"
)

// The wire log (est.ServerConfig.WireLog) on the EST server's own router and this backend: each exchange on an
// attest-* resource is recorded as it crossed the wire, the exchange is the one the same server gives without the log,
// and other resources are not recorded. The enrollment request is a real one, the reference implementation's from a
// GCP SEV-SNP run (../refvectors/testdata); the backend serves no Target, so it refuses each request as a deployment
// that does not serve the Target would.

type wireLine struct {
	Method              string `json:"method"`
	Path                string `json:"path"`
	Query               string `json:"query"`
	RequestContentType  string `json:"request_content_type"`
	RequestBody         string `json:"request_body"`
	RequestBodyBase64   string `json:"request_body_base64"`
	Status              int    `json:"status"`
	ResponseContentType string `json:"response_content_type"`
	ResponseBody        string `json:"response_body"`
	ResponseBodyBase64  string `json:"response_body_base64"`
}

func realEnrollmentRequest(t *testing.T) []byte {
	t.Helper()
	raw, err := os.ReadFile("../refvectors/testdata/tacra-est-ref-vectors-sev-snp.json")
	if err != nil {
		t.Fatal(err)
	}
	var v struct {
		Enrollment struct {
			Request json.RawMessage `json:"AttestedEnrollmentRequest"`
		} `json:"enrollment"`
	}
	if err := json.Unmarshal(raw, &v); err != nil || len(v.Enrollment.Request) == 0 {
		t.Fatalf("the reference enrollment request: %v", err)
	}
	return v.Enrollment.Request
}

func router(t *testing.T, wire *bytes.Buffer) http.Handler {
	t.Helper()
	b, err := New(Config{AcceptableEvidence: []string{"application/vnd.veraison.tsm-report+cbor"}})
	if err != nil {
		t.Fatal(err)
	}
	cfg := &est.ServerConfig{CA: b}
	if wire != nil {
		cfg.WireLog = wire
	}
	h, err := est.NewRouter(cfg)
	if err != nil {
		t.Fatal(err)
	}
	return h
}

func TestWireLogRecordsTheExchange(t *testing.T) {
	enroll := realEnrollmentRequest(t)
	// the same request after 64 KiB of white space, which JSON allows before a value: over the server's limit on
	// request bodies before the request begins
	oversize := append(bytes.Repeat([]byte(" "), 65536), enroll...)
	cases := []struct {
		name, method, target, ctype string
		body                        []byte
		recorded                    bool
	}{
		{"attest-initiate", http.MethodGet,
			"/.well-known/est/attest-initiate?credential_type=x509&target=https%3A%2F%2Fdb.tacra.example", "", nil, true},
		{"attest-enroll, a real request", http.MethodPost, "/.well-known/est/attest-enroll",
			"application/est-attest-enroll+json", enroll, true},
		{"attest-retrieve under a CA label, as text/plain", http.MethodPost,
			"/.well-known/est/arbitraryLabel1/attest-retrieve", "text/plain", enroll, true},
		{"attest-enroll, over the size limit", http.MethodPost, "/.well-known/est/attest-enroll",
			"application/est-attest-enroll+json", oversize, true},
		{"cacerts", http.MethodGet, "/.well-known/est/cacerts", "", nil, false},
	}

	var wire bytes.Buffer
	logged, plain := router(t, &wire), router(t, nil)
	var want []wireLine
	for _, c := range cases {
		serve := func(h http.Handler) *httptest.ResponseRecorder {
			req := httptest.NewRequest(c.method, c.target, bytes.NewReader(c.body))
			if c.ctype != "" {
				req.Header.Set("Content-Type", c.ctype)
			}
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, req)
			return rec
		}
		got, without := serve(logged), serve(plain)
		if got.Code != without.Code || got.Header().Get("Content-Type") != without.Header().Get("Content-Type") ||
			!bytes.Equal(got.Body.Bytes(), without.Body.Bytes()) {
			t.Errorf("%s: with the wire log %d %q %q, without it %d %q %q", c.name, got.Code,
				got.Header().Get("Content-Type"), got.Body.String(), without.Code,
				without.Header().Get("Content-Type"), without.Body.String())
		}
		if !c.recorded {
			continue
		}
		path, query, _ := strings.Cut(c.target, "?")
		body := c.body
		if len(body) > 65536 {
			body = body[:65536] // what the server read before the size limit refused the rest
		}
		want = append(want, wireLine{Method: c.method, Path: path, Query: query, RequestContentType: c.ctype,
			RequestBody: string(body), Status: got.Code, ResponseContentType: got.Header().Get("Content-Type"),
			ResponseBody: got.Body.String()})
	}

	var lines []wireLine
	sc := bufio.NewScanner(&wire)
	sc.Buffer(make([]byte, 0, 1<<20), 1<<20)
	for sc.Scan() {
		var l wireLine
		if err := json.Unmarshal(sc.Bytes(), &l); err != nil {
			t.Fatalf("a wire log line is not JSON: %v", err)
		}
		lines = append(lines, l)
	}
	if len(lines) != len(want) {
		t.Fatalf("%d lines in the wire log, want %d, one for each attest-* exchange", len(lines), len(want))
	}
	for i := range want {
		if lines[i] != want[i] {
			t.Errorf("line %d: %+v\nwant %+v", i+1, lines[i], want[i])
		}
	}
	// what each refusal was, so that the cases test what they say
	for i, st := range []int{http.StatusNotFound, http.StatusNotFound, http.StatusUnsupportedMediaType,
		http.StatusRequestEntityTooLarge} {
		if lines[i].Status != st {
			t.Errorf("%s: status %d, want %d", cases[i].name, lines[i].Status, st)
		}
	}
}
