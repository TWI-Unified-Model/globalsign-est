package main

import (
	"context"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	caapiv1 "github.com/TWI-Unified-Model/tacra/gen/go/caapi/v1"
	"github.com/globalsign/est"
	"github.com/globalsign/est/internal/mockca"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
)

const (
	enrollTarget   = "https://enroll.example"
	retrieveTarget = "https://retrieve.example"
)

// newConduit is the EST Client in front of an EST server over TLS that serves the three attest operations with the
// mock CA, the mock TEE provider and the mock Verifier of this repository: one Target that enrolls, one that retrieves.
func newConduit(t *testing.T) (*conduit, *ecdsa.PrivateKey) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	provider, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	ca, err := mockca.NewTransient()
	if err != nil {
		t.Fatal(err)
	}
	attested := mockca.NewAttested(ca, []mockca.TargetPolicy{
		{Name: enrollTarget, Mechanism: est.MechanismEnroll, FreshnessKind: est.FreshnessPresentNonce, CredentialTypes: []string{est.CredentialTypeX509}},
		{Name: retrieveTarget, Mechanism: est.MechanismRetrieve, FreshnessKind: est.FreshnessPresentNonce, CredentialTypes: []string{est.CredentialTypeAPIKey}},
	}, &provider.PublicKey)

	serverKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject: pkix.Name{CommonName: "EST server"}, DNSNames: []string{"localhost"}, IPAddresses: []net.IP{net.ParseIP("127.0.0.1")},
	}, serverKey)
	if err != nil {
		t.Fatal(err)
	}
	csr, err := x509.ParseCertificateRequest(der)
	if err != nil {
		t.Fatal(err)
	}
	serverCert, err := ca.Enroll(ctx, csr, "", nil)
	if err != nil {
		t.Fatal(err)
	}
	caCerts, err := ca.CACerts(ctx, "", nil)
	if err != nil {
		t.Fatal(err)
	}
	router, err := est.NewRouter(&est.ServerConfig{CA: attested, Timeout: 10 * time.Second, AllowedHosts: []string{"localhost"}, RateLimit: 1000})
	if err != nil {
		t.Fatal(err)
	}
	s := httptest.NewUnstartedServer(router)
	chain := [][]byte{serverCert.Raw}
	for _, c := range caCerts[:len(caCerts)-1] {
		chain = append(chain, c.Raw)
	}
	s.TLS = &tls.Config{Certificates: []tls.Certificate{{Certificate: chain, PrivateKey: serverKey, Leaf: serverCert}}}
	s.StartTLS()
	t.Cleanup(s.Close)

	roots := x509.NewCertPool()
	roots.AddCert(caCerts[len(caCerts)-1])
	host := strings.TrimPrefix(s.URL, "https://")
	return &conduit{est: &est.Client{Host: host, ExplicitAnchor: roots, HostHeader: "localhost:" + strings.Split(host, ":")[1]}}, provider
}

// Enroll through CAAPI: Initiate answers with the mode, the Freshness Handle and the CSK algorithm, and Enroll
// returns the certificate of the key of the CSR as PEM.
func TestEnrollThroughCAAPI(t *testing.T) {
	c, provider := newConduit(t)
	ctx := context.Background()

	initiated, err := c.InitiateRemoteAttestation(ctx, &caapiv1.InitiateCredentialAcquistionRequest{Target: enrollTarget, CredentialType: caapiv1.CredentialType_CREDENTIAL_TYPE_X509})
	if err != nil {
		t.Fatalf("Initiate: %v", err)
	}
	if initiated.GetMode() != caapiv1.CredentialAcquisitionMode_ACQUISITION_ENROLL || initiated.GetFreshnessKind() != caapiv1.FreshnessKind_FRESHNESS_KIND_PRESENT_NONCE ||
		len(initiated.GetFreshnessHandle()) == 0 || initiated.SigningAlgorithm == nil || initiated.GetSigningAlgorithm() != caapiv1.SigningAlgorithm_SIGNING_ALGORITHM_ECDSA_P256 {
		t.Fatalf("Initiate answered %v", initiated)
	}

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	csr, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{Subject: pkix.Name{CommonName: "workload"}}, key)
	if err != nil {
		t.Fatal(err)
	}
	evidence, err := est.NewMockEvidence(provider, est.FreshnessPresentNonce, initiated.GetFreshnessHandle(), enrollTarget, csr)
	if err != nil {
		t.Fatal(err)
	}
	enrolled, err := c.EnrollCredential(ctx, &caapiv1.EnrollCredentialRequest{
		Target: enrollTarget, CredentialType: caapiv1.CredentialType_CREDENTIAL_TYPE_X509,
		FreshnessKind: initiated.GetFreshnessKind(), FreshnessElement: initiated.GetFreshnessHandle(),
		Csr: csr, Evidence: evidence, EvidenceProfile: proto.String(est.MockEATProfileType),
	})
	if err != nil {
		t.Fatalf("Enroll: %v", err)
	}
	block, rest := pem.Decode(enrolled.GetPlaintextCredential())
	if block == nil || block.Type != "CERTIFICATE" || len(rest) != 0 {
		t.Fatalf("Enroll returned no PEM certificate: %q", enrolled.GetPlaintextCredential())
	}
	certificate, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	if public, ok := certificate.PublicKey.(*ecdsa.PublicKey); !ok || !public.Equal(&key.PublicKey) {
		t.Fatal("the certificate does not certify the key of the CSR")
	}

	// The same Evidence a second time: the EST server refuses, and the refusal is not "unavailable".
	_, err = c.EnrollCredential(ctx, &caapiv1.EnrollCredentialRequest{
		Target: enrollTarget, CredentialType: caapiv1.CredentialType_CREDENTIAL_TYPE_X509,
		FreshnessKind: initiated.GetFreshnessKind(), FreshnessElement: initiated.GetFreshnessHandle(),
		Csr: csr, Evidence: evidence, EvidenceProfile: proto.String(est.MockEATProfileType),
	})
	if code := status.Code(err); err == nil || code == codes.Unavailable || code == codes.OK {
		t.Fatalf("the second Enroll with the same Handle: got %v, want a refusal of the EST server", err)
	}
}

// Retrieve through CAAPI: Initiate names the CEK suite, and Retrieve returns the container as the EST server
// answered it, which the CEK opens.
func TestRetrieveThroughCAAPI(t *testing.T) {
	c, provider := newConduit(t)
	ctx := context.Background()

	initiated, err := c.InitiateRemoteAttestation(ctx, &caapiv1.InitiateCredentialAcquistionRequest{Target: retrieveTarget, CredentialType: caapiv1.CredentialType_CREDENTIAL_TYPE_API_KEY})
	if err != nil {
		t.Fatalf("Initiate: %v", err)
	}
	if initiated.GetMode() != caapiv1.CredentialAcquisitionMode_ACQUISITION_RETRIEVE || len(initiated.GetFreshnessHandle()) == 0 || initiated.EncryptionAlgorithm == nil {
		t.Fatalf("Initiate answered %v", initiated)
	}

	cek, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	cekPub, err := x509.MarshalPKIXPublicKey(cek.PublicKey())
	if err != nil {
		t.Fatal(err)
	}
	evidence, err := est.NewMockEvidence(provider, est.FreshnessPresentNonce, initiated.GetFreshnessHandle(), retrieveTarget, cekPub)
	if err != nil {
		t.Fatal(err)
	}
	retrieved, err := c.RetrieveCredential(ctx, &caapiv1.RetrieveCredentialRequest{
		Target: retrieveTarget, CredentialType: caapiv1.CredentialType_CREDENTIAL_TYPE_API_KEY,
		FreshnessKind: initiated.GetFreshnessKind(), FreshnessElement: initiated.GetFreshnessHandle(),
		CekPub: cekPub, Evidence: evidence, EvidenceProfile: proto.String(est.MockEATProfileType),
	})
	if err != nil {
		t.Fatalf("Retrieve: %v", err)
	}
	var sealed est.EncryptedCredentialBundle
	if err := json.Unmarshal(retrieved.GetWrappedCredential(), &sealed); err != nil {
		t.Fatalf("Retrieve returned no container: %v", err)
	}
	if _, err := sealed.Open(cek, cekPub, retrieveTarget, initiated.GetFreshnessHandle(), ""); err != nil {
		t.Fatalf("the CEK does not open the container: %v", err)
	}
}

func TestInitiateRefusals(t *testing.T) {
	c, _ := newConduit(t)
	ctx := context.Background()

	_, err := c.InitiateRemoteAttestation(ctx, &caapiv1.InitiateCredentialAcquistionRequest{Target: enrollTarget, CredentialType: caapiv1.CredentialType(99)})
	if status.Code(err) != codes.InvalidArgument || !strings.Contains(err.Error(), "is not defined by TACRA") {
		t.Errorf("a Credential Type that TACRA does not define: got %v", err)
	}
	// A Target that the EST server does not know: its refusal reaches the caller with its reason, not as "unavailable".
	_, err = c.InitiateRemoteAttestation(ctx, &caapiv1.InitiateCredentialAcquistionRequest{Target: "https://unknown.example", CredentialType: caapiv1.CredentialType_CREDENTIAL_TYPE_X509})
	if code := status.Code(err); err == nil || code == codes.OK || code == codes.Unavailable {
		t.Errorf("an unknown Target: got %v, want the refusal of the EST server", err)
	}
}

type refused struct{ status int }

func (r refused) StatusCode() int { return r.status }
func (r refused) Error() string   { return "refused" }
func (r refused) RetryAfter() int { return 0 }

// A refusal of the EST server reaches the caller of CAAPI as the gRPC status of the same reason.
func TestGRPCError(t *testing.T) {
	for _, c := range []struct {
		err  error
		code codes.Code
	}{
		{refused{http.StatusBadRequest}, codes.InvalidArgument},
		{refused{http.StatusRequestEntityTooLarge}, codes.InvalidArgument},
		{refused{http.StatusUnsupportedMediaType}, codes.InvalidArgument},
		{refused{http.StatusNotFound}, codes.NotFound},
		{refused{http.StatusUnprocessableEntity}, codes.Unimplemented},
		{refused{http.StatusForbidden}, codes.PermissionDenied},
		{refused{http.StatusUnauthorized}, codes.PermissionDenied},
		{refused{http.StatusTooManyRequests}, codes.ResourceExhausted},
		{refused{http.StatusServiceUnavailable}, codes.Unavailable},
		{refused{http.StatusInternalServerError}, codes.Unavailable},
		{errors.New("connection refused"), codes.Unavailable},
	} {
		if got := status.Code(grpcError(c.err)); got != c.code {
			t.Errorf("%v: got %v, want %v", c.err, got, c.code)
		}
	}
}

// Every Freshness Kind of EST has one Freshness Kind of CAAPI, and back.
func TestFreshnessKinds(t *testing.T) {
	if len(freshnessKinds) != len(caapiv1.FreshnessKind_name)-1 {
		t.Fatalf("%d Freshness Kinds of EST for %d of CAAPI", len(freshnessKinds), len(caapiv1.FreshnessKind_name)-1)
	}
	for name, kind := range freshnessKinds {
		if freshnessKindName(kind) != name {
			t.Errorf("%s -> %v -> %q", name, kind, freshnessKindName(kind))
		}
	}
	if freshnessKindName(caapiv1.FreshnessKind_FRESHNESS_KIND_UNSPECIFIED) != "" {
		t.Error("the unspecified Freshness Kind must have no name")
	}
}
