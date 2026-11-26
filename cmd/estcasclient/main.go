// Command estcasclient is the CAS Client of the EST binding of TACRA: it serves
// the Credential Acquisition API (CAAPI) to the CAI beside it and carries each
// call to the EST server as the attest-initiate, attest-enroll and
// attest-retrieve resources of draft-novak-lamps-tacra-est. It is a conduit: it
// holds no key of the Workload, appraises nothing and opens no container.
//
// Environment:
//
//	EST_CLIENT_LISTEN  address of the CAAPI service (default ":9090")
//	EST_SERVER         host and port of the EST server (default "localhost:8443")
//	EST_SERVER_CA      file of the certificate under which the EST server serves TLS, PEM
package main

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"slices"

	caapiv1 "github.com/TWI-Unified-Model/tacra/gen/go/caapi/v1"
	"github.com/globalsign/est"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// bindingHash is the hash of the binding value that the request declares.
const bindingHash = "sha512"

// conduit serves CAAPI over one EST server.
type conduit struct {
	caapiv1.UnimplementedCredentialAcquisitionServiceServer
	est *est.Client
}

var credentialTypes = map[caapiv1.CredentialType]string{
	caapiv1.CredentialType_CREDENTIAL_TYPE_JWT:     est.CredentialTypeJWT,
	caapiv1.CredentialType_CREDENTIAL_TYPE_PSK:     est.CredentialTypePSK,
	caapiv1.CredentialType_CREDENTIAL_TYPE_API_KEY: est.CredentialTypeAPIKey,
	caapiv1.CredentialType_CREDENTIAL_TYPE_X509:    est.CredentialTypeX509,
	caapiv1.CredentialType_CREDENTIAL_TYPE_WIC:     est.CredentialTypeWIC,
	caapiv1.CredentialType_CREDENTIAL_TYPE_WIT:     est.CredentialTypeWIT,
}

var freshnessKinds = map[string]caapiv1.FreshnessKind{
	est.FreshnessAbsentNone:      caapiv1.FreshnessKind_FRESHNESS_KIND_ABSENT_NONE,
	est.FreshnessAbsentTimestamp: caapiv1.FreshnessKind_FRESHNESS_KIND_ABSENT_TIMESTAMP,
	est.FreshnessAbsentEpoch:     caapiv1.FreshnessKind_FRESHNESS_KIND_ABSENT_EPOCH,
	est.FreshnessPresentNonce:    caapiv1.FreshnessKind_FRESHNESS_KIND_PRESENT_NONCE,
	est.FreshnessPresentEpoch:    caapiv1.FreshnessKind_FRESHNESS_KIND_PRESENT_EPOCH,
}

// freshnessKindName is the name of a Freshness Kind as the EST profile spells
// it, or empty for a kind that the profile does not define.
func freshnessKindName(kind caapiv1.FreshnessKind) string {
	for name, value := range freshnessKinds {
		if value == kind {
			return name
		}
	}
	return ""
}

func credentialType(t caapiv1.CredentialType) (string, error) {
	name, ok := credentialTypes[t]
	if !ok {
		return "", status.Errorf(codes.InvalidArgument, "Credential Type %v is not defined by TACRA", t)
	}
	return name, nil
}

// grpcError turns a refusal of the EST server into the gRPC status that the
// CAI reads, with the reason that the EST server gave.
func grpcError(err error) error {
	var refusal est.Error
	if !errors.As(err, &refusal) {
		return status.Error(codes.Unavailable, err.Error())
	}
	switch refusal.StatusCode() {
	case http.StatusBadRequest, http.StatusRequestEntityTooLarge, http.StatusUnsupportedMediaType:
		return status.Error(codes.InvalidArgument, refusal.Error())
	case http.StatusNotFound:
		return status.Error(codes.NotFound, refusal.Error())
	case http.StatusUnprocessableEntity:
		// A Credential Type that the Target does not serve: gRPC defines
		// Unimplemented as not supported in this service.
		return status.Error(codes.Unimplemented, refusal.Error())
	case http.StatusForbidden, http.StatusUnauthorized:
		return status.Error(codes.PermissionDenied, refusal.Error())
	case http.StatusTooManyRequests:
		return status.Error(codes.ResourceExhausted, refusal.Error())
	}
	return status.Error(codes.Unavailable, refusal.Error())
}

func optional(s *string) *string {
	if s == nil || *s == "" {
		return nil
	}
	return s
}

// InitiateRemoteAttestation is attest-initiate.
func (c *conduit) InitiateRemoteAttestation(ctx context.Context, in *caapiv1.InitiateCredentialAcquistionRequest) (*caapiv1.InitiateCredentialAcquisitionResponse, error) {
	name, err := credentialType(in.GetCredentialType())
	if err != nil {
		return nil, err
	}
	answer, err := c.est.InitiateRemoteAttestation(ctx, in.GetTarget(), name, in.GetCredentialHint())
	if err != nil {
		return nil, grpcError(err)
	}
	out := &caapiv1.InitiateCredentialAcquisitionResponse{FreshnessKind: freshnessKinds[answer.FreshnessKind]}
	if len(answer.Handle) > 0 {
		out.FreshnessHandle = answer.Handle
	}
	switch answer.Mechanism {
	case est.MechanismEnroll:
		out.Mode = caapiv1.CredentialAcquisitionMode_ACQUISITION_ENROLL
		if slices.Contains(answer.AcceptableCSK, est.SigECDSAP256SHA256) {
			out.SigningAlgorithm = caapiv1.SigningAlgorithm_SIGNING_ALGORITHM_ECDSA_P256.Enum()
		}
	case est.MechanismRetrieve:
		out.Mode = caapiv1.CredentialAcquisitionMode_ACQUISITION_RETRIEVE
		// The hybrid suite of the container first, when the EST server accepts it.
		switch {
		case slices.Contains(answer.AcceptableCEK, est.AcceptableCEKMLKEM768P256):
			out.EncryptionAlgorithm = caapiv1.EncryptionAlgorithm_ENCRYPTION_ALGORITHM_MLKEM768_P256.Enum()
		case slices.Contains(answer.AcceptableCEK, est.AcceptableCEKDHKEMP256):
			out.EncryptionAlgorithm = caapiv1.EncryptionAlgorithm_ENCRYPTION_ALGORITHM_ECDH_P256.Enum()
		}
	}
	return out, nil
}

// EnrollCredential is attest-enroll.
func (c *conduit) EnrollCredential(ctx context.Context, in *caapiv1.EnrollCredentialRequest) (*caapiv1.EnrollCredentialResponse, error) {
	name, err := credentialType(in.GetCredentialType())
	if err != nil {
		return nil, err
	}
	certificate, err := c.est.EnrollCredential(ctx, &est.AttestedEnrollmentRequest{
		Target:         in.GetTarget(),
		CredentialType: name,
		FreshnessKind:  freshnessKindName(in.GetFreshnessKind()),
		Handle:         in.GetFreshnessElement(),
		CSR:            in.GetCsr(),
		Evidence:       in.GetEvidence(),
		Binding:        est.Binding{Method: est.BindingInput, Hash: bindingHash},
		Profile:        in.GetEvidenceProfile(),
		CredentialHint: optional(in.CredentialHint),
	})
	if err != nil {
		return nil, grpcError(err)
	}
	// The credential goes back as a PEM certificate bundle, which here is the one certificate.
	bundle := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certificate.Raw})
	return &caapiv1.EnrollCredentialResponse{PlaintextCredential: bundle}, nil
}

// RetrieveCredential is attest-retrieve. The container goes back to the CAI as
// the EST server answered it.
func (c *conduit) RetrieveCredential(ctx context.Context, in *caapiv1.RetrieveCredentialRequest) (*caapiv1.RetrieveCredentialResponse, error) {
	name, err := credentialType(in.GetCredentialType())
	if err != nil {
		return nil, err
	}
	sealed, err := c.est.RetrieveCredentialRaw(ctx, &est.AttestedRetrievalRequest{
		Target:         in.GetTarget(),
		CredentialType: name,
		FreshnessKind:  freshnessKindName(in.GetFreshnessKind()),
		Handle:         in.GetFreshnessElement(),
		CEKPub:         in.GetCekPub(),
		Evidence:       in.GetEvidence(),
		Binding:        est.Binding{Method: est.BindingInput, Hash: bindingHash},
		Profile:        in.GetEvidenceProfile(),
		CredentialHint: optional(in.CredentialHint),
	})
	if err != nil {
		return nil, grpcError(err)
	}
	return &caapiv1.RetrieveCredentialResponse{WrappedCredential: sealed}, nil
}

func main() {
	listen := envOr("EST_CLIENT_LISTEN", ":9090")
	server := envOr("EST_SERVER", "localhost:8443")
	anchorPath := os.Getenv("EST_SERVER_CA")
	if anchorPath == "" {
		fail("EST_SERVER_CA is required: the certificate under which the EST server serves TLS")
	}
	anchor, err := os.ReadFile(anchorPath)
	if err != nil {
		fail("EST_SERVER_CA: %v", err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(anchor) {
		fail("EST_SERVER_CA: no certificate in %s", anchorPath)
	}
	ln, err := net.Listen("tcp", listen)
	if err != nil {
		fail("listen %s: %v", listen, err)
	}
	s := grpc.NewServer()
	caapiv1.RegisterCredentialAcquisitionServiceServer(s, &conduit{est: &est.Client{Host: server, ExplicitAnchor: pool}})
	fmt.Printf("EST Client: CAAPI on %s, EST server %s\n", listen, server)
	if err := s.Serve(ln); err != nil {
		fail("EST Client failed: %v", err)
	}
}

func fail(format string, args ...any) {
	fmt.Fprintf(os.Stderr, format+"\n", args...)
	os.Exit(1)
}

func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}
