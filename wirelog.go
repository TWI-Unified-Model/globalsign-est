package est

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"path"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/go-chi/chi/v5/middleware"
)

// wireRecord is one exchange on an attest-* resource, as ServerConfig.WireLog records it: the request and the response
// as they crossed the wire. A body that is not valid UTF-8 is recorded in base64, under the name ending in _base64.
type wireRecord struct {
	Time                string `json:"time"`
	RequestID           string `json:"request_id,omitempty"`
	Method              string `json:"method"`
	Path                string `json:"path"`
	Query               string `json:"query,omitempty"`
	RequestContentType  string `json:"request_content_type,omitempty"`
	RequestBody         string `json:"request_body,omitempty"`
	RequestBodyBase64   string `json:"request_body_base64,omitempty"`
	Status              int    `json:"status"`
	ResponseContentType string `json:"response_content_type,omitempty"`
	ResponseBody        string `json:"response_body,omitempty"`
	ResponseBodyBase64  string `json:"response_body_base64,omitempty"`
}

// errReader returns err on every read: what the handler reads after the bytes withWireLog read ahead of it, when the
// request body ended in an error, such as the size limit's.
type errReader struct{ err error }

func (e errReader) Read([]byte) (int, error) { return 0, e.err }

// wireBody is a body as wireRecord carries it: as text when it is valid UTF-8, in base64 otherwise.
func wireBody(b []byte) (text, b64 string) {
	switch {
	case len(b) == 0:
		return "", ""
	case utf8.Valid(b):
		return string(b), ""
	default:
		return "", base64.StdEncoding.EncodeToString(b)
	}
}

// withWireLog is middleware that writes a wireRecord to w for every exchange on an attest-* resource, with or without
// the additional path segment, and lets every other request pass unrecorded. It reads the request body ahead of the
// handler and gives the handler the same bytes, and the same error when the body ends in one, so the exchange is the
// one there would have been without the record. Headers other than Content-Type, Authorization among them, are not
// recorded.
func withWireLog(w io.Writer) func(next http.Handler) http.Handler {
	var mu sync.Mutex

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
			if !strings.HasPrefix(path.Base(r.URL.Path), "attest-") {
				next.ServeHTTP(rw, r)
				return
			}

			body, err := io.ReadAll(r.Body)
			if err != nil {
				r.Body = io.NopCloser(io.MultiReader(bytes.NewReader(body), errReader{err}))
			} else {
				r.Body = io.NopCloser(bytes.NewReader(body))
			}

			ww := middleware.NewWrapResponseWriter(rw, r.ProtoMajor)
			var resp bytes.Buffer
			ww.Tee(&resp)

			next.ServeHTTP(ww, r)

			rec := wireRecord{
				Time:                time.Now().UTC().Format(time.RFC3339Nano),
				RequestID:           middleware.GetReqID(r.Context()),
				Method:              r.Method,
				Path:                r.URL.Path,
				Query:               r.URL.RawQuery,
				RequestContentType:  r.Header.Get(contentTypeHeader),
				Status:              ww.Status(),
				ResponseContentType: ww.Header().Get(contentTypeHeader),
			}
			rec.RequestBody, rec.RequestBodyBase64 = wireBody(body)
			rec.ResponseBody, rec.ResponseBodyBase64 = wireBody(resp.Bytes())

			line, err := json.Marshal(rec)
			if err != nil {
				LoggerFromContext(r.Context()).Errorf("failed to marshal the wire record: %v", err)
				return
			}

			mu.Lock()
			defer mu.Unlock()
			if _, err := w.Write(append(line, '\n')); err != nil {
				LoggerFromContext(r.Context()).Errorf("failed to write the wire record: %v", err)
			}
		})
	}
}
