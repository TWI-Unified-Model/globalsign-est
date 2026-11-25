package cas

import (
	"context"
	"crypto/x509"
	"errors"
	"net/http"
	"strings"
	"testing"

	"github.com/TWI-Unified-Model/tacra/casserver"
	"github.com/TWI-Unified-Model/tacra/constants"
	"github.com/globalsign/est"
	"github.com/sirupsen/logrus"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// A refusal of the plug-in names its reason as a gRPC status. The EST server answers with the HTTP status of the
// same reason and the same text.
func TestRefusal(t *testing.T) {
	if refusal(nil) != nil {
		t.Fatal("no error must stay no error")
	}
	for _, c := range []struct {
		name   string
		err    error
		status int
		text   string
	}{
		{"a request that is not well formed", status.Error(codes.InvalidArgument, "CSR must be specified"), http.StatusBadRequest, "CSR must be specified"},
		{"a Target or a Freshness Handle that is not known", status.Error(codes.NotFound, "unknown Freshness Handle"), http.StatusNotFound, "unknown Freshness Handle"},
		{"a refusal of policy or of attestation", status.Error(codes.PermissionDenied, "remote attestation failed"), http.StatusForbidden, "remote attestation failed"},
		{"a Credential Type that the Target does not serve", status.Error(codes.Unimplemented, "not served"), http.StatusUnprocessableEntity, "not served"},
		{"too many requests", status.Error(codes.ResourceExhausted, "slow down"), http.StatusTooManyRequests, "slow down"},
		{"a Verifier that does not answer", status.Error(codes.Unavailable, "the Verifier is unavailable"), http.StatusServiceUnavailable, "the Verifier is unavailable"},
		{"any other status of the plug-in", status.Error(codes.Internal, "encoding the container"), http.StatusInternalServerError, "encoding the container"},
		{"an error that is not a status", errors.New("ohno"), http.StatusInternalServerError, "ohno"},
		{"an error that already carries an HTTP status", fail(http.StatusBadGateway, "no certificate"), http.StatusBadGateway, "no certificate"},
	} {
		got, ok := refusal(c.err).(est.Error)
		if !ok {
			t.Errorf("%s: the refusal does not carry an HTTP status", c.name)
			continue
		}
		if got.StatusCode() != c.status || got.Error() != c.text {
			t.Errorf("%s: got %d %q, want %d %q", c.name, got.StatusCode(), got.Error(), c.status, c.text)
		}
	}
}

// A Target in enroll mode needs a Credential Authority: this EST server has no CA of its own.
func TestNewRefusesEnrollWithoutACredentialAuthority(t *testing.T) {
	cfg := &Config{Config: casserver.Config{
		Target: map[string]*casserver.TargetConfig{
			"https://server.example": {Mode: constants.CredentialAcquisitionModeEnroll, Verifiers: []string{"veraison"}, Measurements: []string{"a0a1a2"}},
		},
	}}
	_, err := New(cfg, logrus.New())
	if err == nil || !strings.Contains(err.Error(), `Target "https://server.example" is in enroll mode and no credential_authority is configured`) {
		t.Fatalf("got %v, want the refusal that names the Target", err)
	}
}

// The classic resources of EST are not offered by this backend; cacerts answers when ca_certs names certificates.
func TestClassicResources(t *testing.T) {
	ctx := context.Background()
	notOffered := func(name string, err error) {
		t.Helper()
		refused, ok := err.(est.Error)
		if !ok || refused.StatusCode() != http.StatusNotImplemented {
			t.Errorf("%s: got %v, want 501", name, err)
		}
	}
	b := &Backend{}
	_, err := b.CACerts(ctx, "", nil)
	notOffered("cacerts without ca_certs", err)
	_, err = b.Enroll(ctx, nil, "", nil)
	notOffered("simpleenroll", err)
	_, err = b.Reenroll(ctx, nil, nil, "", nil)
	notOffered("simplereenroll", err)
	_, _, err = b.ServerKeyGen(ctx, nil, "", nil)
	notOffered("serverkeygen", err)
	_, _, _, err = b.TPMEnroll(ctx, nil, nil, nil, nil, "", nil)
	notOffered("tpmenroll", err)
	if attrs, err := b.CSRAttrs(ctx, "", nil); err != nil || len(attrs.OIDs) != 0 || len(attrs.Attributes) != 0 {
		t.Errorf("csrattrs: got %+v, %v, want none", attrs, err)
	}

	chain := []*x509.Certificate{{Raw: []byte{1}}, {Raw: []byte{2}}}
	b.cacerts = chain
	got, err := b.CACerts(ctx, "", nil)
	if err != nil || len(got) != 2 || got[0] != chain[0] || got[1] != chain[1] {
		t.Errorf("cacerts: got %v, %v, want the certificates of ca_certs", got, err)
	}
}
