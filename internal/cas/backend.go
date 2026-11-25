// Package cas is an EST server backend that hosts the CAS Server Plug-in of TACRA
// (github.com/TWI-Unified-Model/tacra/casserver). The EST server is then the Credential Acquisition System Server
// and the RATS Relying Party at once: it issues the Freshness Handle, sends the Evidence to a Verifier, verifies the
// Attestation Results and the binding of the key to the Evidence, has the configured Credential Authority certify
// the key of an Enrollment, and reads and seals the credential of a Retrieval. The EST resources attest-initiate,
// attest-enroll and attest-retrieve carry the three calls; the plug-in decides.
package cas

import (
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"net/http"

	"github.com/TWI-Unified-Model/tacra/casserver"
	"github.com/TWI-Unified-Model/tacra/constants"
	"github.com/globalsign/est"
	"github.com/globalsign/pemfile"
	"github.com/sirupsen/logrus"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// Config is the section of the backend in the EST server configuration: the configuration of the plug-in, and the
// certificates that the cacerts resource answers with.
type Config struct {
	casserver.Config

	// CACerts is the file holding the PEM chain of the Credential Authority, which /cacerts returns.
	CACerts string `json:"ca_certs,omitempty"`
}

// Backend implements est.CA, est.AttestationCA and est.RawRetriever on the plug-in.
type Backend struct {
	acquirer *casserver.Acquirer
	cacerts  []*x509.Certificate
}

// New builds the backend from its configuration. The plug-in refuses a configuration that it cannot serve.
func New(cfg *Config, log logrus.FieldLogger) (*Backend, error) {
	if cfg.CredentialAuthority == nil {
		for name, target := range cfg.Target {
			if target != nil && target.Mode == constants.CredentialAcquisitionModeEnroll {
				return nil, fmt.Errorf("credential_acquisition: Target %q is in enroll mode and no credential_authority is configured", name)
			}
		}
	}
	acquirer, err := casserver.New(&cfg.Config, log)
	if err != nil {
		return nil, err
	}
	b := &Backend{acquirer: acquirer}
	if cfg.CACerts != "" {
		if b.cacerts, err = pemfile.ReadCerts(cfg.CACerts); err != nil {
			return nil, fmt.Errorf("credential_acquisition: ca_certs: %w", err)
		}
	}
	return b, nil
}

// httpError carries an HTTP status to the error writer of the EST server.
type httpError struct {
	status int
	msg    string
}

func (e *httpError) Error() string   { return e.msg }
func (e *httpError) StatusCode() int { return e.status }
func (e *httpError) RetryAfter() int { return 0 }

func fail(status int, format string, a ...any) error {
	return &httpError{status, fmt.Sprintf(format, a...)}
}

// refusal turns a refusal of the plug-in, a gRPC status that names the reason, into the HTTP status of the EST
// profile with the same reason.
func refusal(err error) error {
	if err == nil {
		return nil
	}
	if already, ok := errors.AsType[*httpError](err); ok {
		return already
	}
	st, ok := status.FromError(err)
	if !ok {
		return fail(http.StatusInternalServerError, "%v", err)
	}
	code := http.StatusInternalServerError
	switch st.Code() {
	case codes.InvalidArgument:
		code = http.StatusBadRequest
	case codes.NotFound:
		code = http.StatusNotFound
	case codes.PermissionDenied:
		code = http.StatusForbidden
	case codes.Unimplemented:
		code = http.StatusUnprocessableEntity // a Credential Type that the Target does not serve
	case codes.ResourceExhausted:
		code = http.StatusTooManyRequests
	case codes.Unavailable:
		code = http.StatusServiceUnavailable
	}
	return fail(code, "%s", st.Message())
}

var errClassic = fail(http.StatusNotImplemented, "this EST server provisions credentials only through the attest-* resources")

// The classic resources of EST are not offered: an attested request is never answered by a classic operation.

func (b *Backend) CACerts(context.Context, string, *http.Request) ([]*x509.Certificate, error) {
	if len(b.cacerts) == 0 {
		return nil, errClassic
	}
	return b.cacerts, nil
}

func (b *Backend) CSRAttrs(context.Context, string, *http.Request) (est.CSRAttrs, error) {
	return est.CSRAttrs{}, nil
}

func (b *Backend) Enroll(context.Context, *x509.CertificateRequest, string, *http.Request) (*x509.Certificate, error) {
	return nil, errClassic
}

func (b *Backend) Reenroll(context.Context, *x509.Certificate, *x509.CertificateRequest, string, *http.Request) (*x509.Certificate, error) {
	return nil, errClassic
}

func (b *Backend) ServerKeyGen(context.Context, *x509.CertificateRequest, string, *http.Request) (*x509.Certificate, []byte, error) {
	return nil, nil, errClassic
}

func (b *Backend) TPMEnroll(context.Context, *x509.CertificateRequest, []*x509.Certificate, []byte, []byte, string, *http.Request) ([]byte, []byte, []byte, error) {
	return nil, nil, nil, errClassic
}

// InitiateRemoteAttestation is attest-initiate: the plug-in validates the Target, the Credential Type and the
// Credential Hint, and answers with the mode and the Freshness Handle.
func (b *Backend) InitiateRemoteAttestation(ctx context.Context, target, credentialType, credentialHint, _ string, _ *http.Request) (*est.AttestationInitiateResponse, error) {
	res, err := b.acquirer.Initiate(ctx, casserver.Initiation{
		Target:         target,
		CredentialType: constants.CredentialType(credentialType),
		CredentialHint: credentialHint,
	})
	if err != nil {
		return nil, refusal(err)
	}
	return &est.AttestationInitiateResponse{
		FreshnessKind:      string(res.FreshnessKind),
		Handle:             res.Handle,
		ExpiresIn:          int(res.ExpiresInSeconds),
		MaxAge:             int(res.MaxAgeSeconds),
		AcceptableEvidence: res.AcceptableEvidence,
		AcceptableCSK:      res.AcceptableCSK,
		AcceptableCEK:      res.AcceptableCEK,
		Mechanism:          string(res.Mode),
	}, nil
}

func hint(h *string) string {
	if h == nil {
		return ""
	}
	return *h
}

// EnrollCredential is attest-enroll: the plug-in appraises, and the configured Credential Authority certifies the
// key of the CSR under the name that the policy for the Target assigns.
func (b *Backend) EnrollCredential(ctx context.Context, req *est.AttestedEnrollmentRequest, _ string, _ *http.Request) (*x509.Certificate, error) {
	enrolled, err := b.acquirer.Enroll(ctx, casserver.Enrollment{
		Target:           req.Target,
		CredentialType:   constants.CredentialType(req.CredentialType),
		CredentialHint:   hint(req.CredentialHint),
		FreshnessKind:    constants.FreshnessKind(req.FreshnessKind),
		FreshnessElement: req.Handle,
		CSR:              req.CSR,
		Evidence:         req.Evidence,
		EvidenceProfile:  req.Profile,
		BindingMethod:    req.Binding.Method,
		BindingHash:      req.Binding.Hash,
	})
	if err != nil {
		return nil, refusal(err)
	}
	chain, err := b.acquirer.IssueCertificate(ctx, enrolled)
	if err != nil {
		return nil, refusal(err)
	}
	certificate, err := x509.ParseCertificate(chain[0])
	if err != nil {
		return nil, fail(http.StatusBadGateway, "the Credential Authority returned no certificate: %v", err)
	}
	return certificate, nil
}

// RetrieveCredential is not used: RetrieveCredentialRaw serves attest-retrieve.
func (b *Backend) RetrieveCredential(context.Context, *est.AttestedRetrievalRequest, string, *http.Request) (*est.EncryptedCredentialBundle, error) {
	return nil, fail(http.StatusInternalServerError, "RetrieveCredentialRaw serves attest-retrieve")
}

// RetrieveCredentialRaw is attest-retrieve: the plug-in appraises, reads the credential for the Target from the
// Secret Vault and seals it to CEKpub. The container is returned as the plug-in produced it.
func (b *Backend) RetrieveCredentialRaw(ctx context.Context, req *est.AttestedRetrievalRequest, _ string, _ *http.Request) ([]byte, error) {
	sealed, err := b.acquirer.Retrieve(ctx, casserver.Retrieval{
		Target:           req.Target,
		CredentialType:   constants.CredentialType(req.CredentialType),
		CredentialHint:   hint(req.CredentialHint),
		FreshnessKind:    constants.FreshnessKind(req.FreshnessKind),
		FreshnessElement: req.Handle,
		CEKPub:           req.CEKPub,
		Evidence:         req.Evidence,
		EvidenceProfile:  req.Profile,
		BindingMethod:    req.Binding.Method,
		BindingHash:      req.Binding.Hash,
	})
	if err != nil {
		return nil, refusal(err)
	}
	return sealed, nil
}
