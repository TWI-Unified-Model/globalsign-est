package est_test

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"net"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/globalsign/est"
	"github.com/globalsign/est/internal/mockca"
)

// The mock path end to end, through the wire: attest-initiate, attest-enroll
// and attest-retrieve for every Freshness Kind against this fork's mock CA,
// mock TEE and mock Verifier, and the refusals a changed input meets. The
// requests cross the wire as a client's do, so the draft's syntax rules apply
// to them (attest_syntax.go).

const (
	flowEpochMarker = "epoch-2026-10-11"
	flowMaxAge      = 120 // seconds: the policy's window for absent-timestamp
	flowStaleBy     = 10 * time.Minute
	flowBindingHash = "sha512"
	flowWorkloadCN  = "workload"
	flowOtherCN     = "other"
	flowOtherTarget = "https://elsewhere.example"
	flowServerCN    = "mock flow EST server"
	flowRateLimit   = 1000
	flowHint        = "payments" // a Credential Hint, for a credential group of its own
	flowBundleItems = 3          // the mock Secret Vault's bundle: certificate, key, CA chain
)

var flowKinds = []string{
	est.FreshnessPresentNonce, est.FreshnessPresentEpoch, est.FreshnessAbsentEpoch,
	est.FreshnessAbsentTimestamp, est.FreshnessAbsentNone,
}

func flowEnrollTarget(kind string) string {
	return "https://db-" + kind + ".example"
}

func flowRetrieveTarget(kind string) string {
	return "https://ledger-" + kind + ".example"
}

// mockFlow is the attested mock CA behind an EST server over TLS, with a
// server certificate from that CA, and a client that trusts the CA.
type mockFlow struct {
	client   *est.Client
	provider *ecdsa.PrivateKey
	issuer   *x509.Certificate
}

func newMockFlow(t *testing.T) *mockFlow {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), testTimeout)
	defer cancel()

	provider, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate mock provider key: %v", err)
	}
	// One Target per Freshness Kind and mechanism: the CAS decides both per
	// Target, opaquely to the Attester.
	var targets []mockca.TargetPolicy
	for _, kind := range flowKinds {
		targets = append(targets,
			mockca.TargetPolicy{
				Name: flowEnrollTarget(kind), Mechanism: est.MechanismEnroll, FreshnessKind: kind,
				EpochMarker: flowEpochMarker, MaxAge: flowMaxAge, CredentialTypes: []string{est.CredentialTypeX509},
			},
			mockca.TargetPolicy{
				Name: flowRetrieveTarget(kind), Mechanism: est.MechanismRetrieve, FreshnessKind: kind,
				EpochMarker: flowEpochMarker, MaxAge: flowMaxAge,
				CredentialTypes: []string{est.CredentialTypeAPIKey, est.CredentialTypeX509},
			},
		)
	}
	ca, err := mockca.NewTransient()
	if err != nil {
		t.Fatalf("failed to create mock CA: %v", err)
	}
	attested := mockca.NewAttested(ca, targets, &provider.PublicKey)

	serverKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate EST server key: %v", err)
	}
	der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject:     pkix.Name{CommonName: flowServerCN},
		DNSNames:    []string{"localhost"},
		IPAddresses: []net.IP{net.ParseIP("127.0.0.1")},
	}, serverKey)
	if err != nil {
		t.Fatalf("failed to create EST server certificate request: %v", err)
	}
	csr, err := x509.ParseCertificateRequest(der)
	if err != nil {
		t.Fatalf("failed to parse EST server certificate request: %v", err)
	}
	serverCert, err := ca.Enroll(ctx, csr, "", nil)
	if err != nil {
		t.Fatalf("failed to enroll for EST server certificate: %v", err)
	}
	caCerts, err := ca.CACerts(ctx, "", nil)
	if err != nil {
		t.Fatalf("failed to obtain CA certificates: %v", err)
	}

	router, err := est.NewRouter(&est.ServerConfig{
		CA: attested, Timeout: testTimeout, AllowedHosts: []string{"localhost"}, RateLimit: flowRateLimit,
	})
	if err != nil {
		t.Fatalf("failed to create router: %v", err)
	}
	s := httptest.NewUnstartedServer(router)
	// The server presents its certificate with the CA's intermediates; the
	// client trusts the root.
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
	client := &est.Client{Host: host, ExplicitAnchor: roots, HostHeader: "localhost:" + strings.Split(host, ":")[1]}
	return &mockFlow{client: client, provider: provider, issuer: caCerts[0]}
}

// handle is the freshness element the Attester binds for kind, after
// attest-initiate for the Target: the Handle the EST server returned for the
// present kinds, the epoch marker the Attester holds, its own clock's
// timestamp element, or nothing.
func (f *mockFlow) handle(t *testing.T, target, credentialType, kind string) []byte {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), testTimeout)
	defer cancel()
	resp, err := f.client.InitiateRemoteAttestation(ctx, target, credentialType)
	if err != nil {
		t.Fatalf("attest-initiate for %s: %v", target, err)
	}
	if resp.FreshnessKind != kind {
		t.Fatalf("attest-initiate for %s: freshness kind %q, want %q", target, resp.FreshnessKind, kind)
	}
	switch kind {
	case est.FreshnessPresentNonce, est.FreshnessPresentEpoch:
		if len(resp.Handle) == 0 {
			t.Fatalf("attest-initiate for %s: no Handle with %s", target, kind)
		}
		return []byte(resp.Handle)
	case est.FreshnessAbsentEpoch:
		return []byte(flowEpochMarker)
	case est.FreshnessAbsentTimestamp:
		return est.TimestampElement(time.Now())
	}
	return nil
}

func (f *mockFlow) evidence(t *testing.T, kind string, handle []byte, target string, subject []byte) []byte {
	t.Helper()
	evidence, err := est.NewMockEvidence(f.provider, kind, handle, target, subject)
	if err != nil {
		t.Fatalf("failed to create mock Evidence: %v", err)
	}
	return evidence
}

func (f *mockFlow) enroll(kind string, handle, csr, evidence []byte) (*x509.Certificate, error) {
	ctx, cancel := context.WithTimeout(context.Background(), testTimeout)
	defer cancel()
	return f.client.EnrollCredential(ctx, &est.AttestedEnrollmentRequest{
		Target: flowEnrollTarget(kind), CredentialType: est.CredentialTypeX509, FreshnessKind: kind,
		Handle: handle, CSR: csr, Evidence: evidence,
		Binding: est.Binding{Method: est.BindingInput, Hash: flowBindingHash}, Profile: est.MockEATProfileType,
	})
}

func (f *mockFlow) retrieve(kind string, handle, cekPub, evidence []byte) (*est.EncryptedCredentialBundle, error) {
	return f.retrieveAs(kind, est.CredentialTypeAPIKey, nil, handle, cekPub, evidence)
}

func (f *mockFlow) retrieveAs(kind, credentialType string, hint *string, handle, cekPub, evidence []byte) (*est.EncryptedCredentialBundle, error) {
	ctx, cancel := context.WithTimeout(context.Background(), testTimeout)
	defer cancel()
	return f.client.RetrieveCredential(ctx, &est.AttestedRetrievalRequest{
		Target: flowRetrieveTarget(kind), CredentialType: credentialType, FreshnessKind: kind,
		Handle: handle, CEKPub: cekPub, Evidence: evidence,
		Binding: est.Binding{Method: est.BindingInput, Hash: flowBindingHash}, Profile: est.MockEATProfileType,
		CredentialHint: hint,
	})
}

// retrieveX509 acquires an x.509 credential by retrieval for the Target of
// kind, with a CEK of its own, and opens the container; it returns the bundle
// and the Evidence the request carried.
func (f *mockFlow) retrieveX509(t *testing.T, kind string, hint *string) (*est.CredentialBundle, []byte) {
	t.Helper()
	target := flowRetrieveTarget(kind)
	cek, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate CEK: %v", err)
	}
	cekPub := cek.PublicKey().Bytes()
	handle := f.handle(t, target, est.CredentialTypeX509, kind)
	evidence := f.evidence(t, kind, handle, target, cekPub)
	sealed, err := f.retrieveAs(kind, est.CredentialTypeX509, hint, handle, cekPub, evidence)
	if err != nil {
		t.Fatalf("retrieval of an x.509 credential: %v", err)
	}
	bundle, err := sealed.Open(cek)
	if err != nil {
		t.Fatalf("container does not open under the CEK: %v", err)
	}
	return bundle, evidence
}

func flowCSR(t *testing.T, commonName string) []byte {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}
	csr, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{Subject: pkix.Name{CommonName: commonName}}, key)
	if err != nil {
		t.Fatalf("failed to create certificate request: %v", err)
	}
	return csr
}

func requireRefusal(t *testing.T, err error, reason string) {
	t.Helper()
	if err == nil || !strings.Contains(err.Error(), reason) {
		t.Fatalf("expected a refusal mentioning %q, got: %v", reason, err)
	}
}

// TestMockFlowEnroll: for every Freshness Kind, Evidence bound to another CSR
// or to another Target is refused, and the honest enrollment yields a
// certificate for the CSR's subject from the mock CA.
func TestMockFlowEnroll(t *testing.T) {
	f := newMockFlow(t)
	for _, kind := range flowKinds {
		t.Run(kind, func(t *testing.T) {
			target := flowEnrollTarget(kind)
			csr := flowCSR(t, flowWorkloadCN)

			handle := f.handle(t, target, est.CredentialTypeX509, kind)
			_, err := f.enroll(kind, handle, flowCSR(t, flowOtherCN), f.evidence(t, kind, handle, target, csr))
			requireRefusal(t, err, "not bound")

			handle = f.handle(t, target, est.CredentialTypeX509, kind)
			_, err = f.enroll(kind, handle, csr, f.evidence(t, kind, handle, flowOtherTarget, csr))
			requireRefusal(t, err, "not bound")

			handle = f.handle(t, target, est.CredentialTypeX509, kind)
			cert, err := f.enroll(kind, handle, csr, f.evidence(t, kind, handle, target, csr))
			if err != nil {
				t.Fatalf("enrollment: %v", err)
			}
			if cert.Subject.CommonName != flowWorkloadCN {
				t.Fatalf("certificate for %q, want %q", cert.Subject.CommonName, flowWorkloadCN)
			}
			if err := cert.CheckSignatureFrom(f.issuer); err != nil {
				t.Fatalf("certificate not from the mock CA: %v", err)
			}
		})
	}
}

// TestMockFlowRetrieve: for every Freshness Kind, the container is sealed to
// the CEK the request carried, names the Target and the handle it was made
// for, and opens under no other key.
func TestMockFlowRetrieve(t *testing.T) {
	f := newMockFlow(t)
	for _, kind := range flowKinds {
		t.Run(kind, func(t *testing.T) {
			target := flowRetrieveTarget(kind)
			cek, err := ecdh.P256().GenerateKey(rand.Reader)
			if err != nil {
				t.Fatalf("failed to generate CEK: %v", err)
			}
			cekPub := cek.PublicKey().Bytes()
			handle := f.handle(t, target, est.CredentialTypeAPIKey, kind)
			sealed, err := f.retrieve(kind, handle, cekPub, f.evidence(t, kind, handle, target, cekPub))
			if err != nil {
				t.Fatalf("retrieval: %v", err)
			}
			if sealed.Target != target || !bytes.Equal(sealed.Handle, handle) {
				t.Fatalf("container for %q with handle %x, want %q with %x", sealed.Target, sealed.Handle, target, handle)
			}
			bundle, err := sealed.Open(cek)
			if err != nil {
				t.Fatalf("container does not open under the CEK: %v", err)
			}
			if bundle.GroupID != sealed.GroupID || len(bundle.CredentialItems) == 0 {
				t.Fatalf("bundle of group %q with %d items, container of group %q", bundle.GroupID, len(bundle.CredentialItems), sealed.GroupID)
			}
			other, err := ecdh.P256().GenerateKey(rand.Reader)
			if err != nil {
				t.Fatalf("failed to generate another CEK: %v", err)
			}
			if _, err := sealed.Open(other); err == nil {
				t.Fatal("container opened under another CEK")
			}
		})
	}
}

// TestMockFlowRetrieveX509Credential: attest-retrieve of an x.509 credential
// releases, in the container sealed to the CEK, a certificate the mock CA
// issued to the attested workload, the PKCS#8 private key that matches it and
// the CA's chain; a replica of the workload (the same Evidence profile and
// Credential Hint) is given the same credential, another Credential Hint a
// credential of another group.
func TestMockFlowRetrieveX509Credential(t *testing.T) {
	f := newMockFlow(t)
	kind := est.FreshnessPresentNonce
	bundle, evidence := f.retrieveX509(t, kind, nil)

	items := map[string][]byte{}
	for _, item := range bundle.CredentialItems {
		items[item.Type] = item.Data
	}
	if len(items) != flowBundleItems {
		t.Fatalf("bundle with %d item types, want %d: %v", len(items), flowBundleItems, bundle.CredentialItems)
	}
	for _, typ := range []string{est.CredentialItemX509Cert, est.CredentialItemPKCS8Key, est.CredentialItemCACertsPEM} {
		if len(items[typ]) == 0 {
			t.Fatalf("bundle without a %q item", typ)
		}
	}

	// the certificate: issued to the attested workload, by the mock CA
	cert, err := x509.ParseCertificate(items[est.CredentialItemX509Cert])
	if err != nil {
		t.Fatalf("certificate: %v", err)
	}
	claims, err := est.VerifyMockEvidence(evidence, &f.provider.PublicKey)
	if err != nil {
		t.Fatalf("the request's Evidence: %v", err)
	}
	attested := claims.Issuer + ":" + hex.EncodeToString(claims.PCRs[est.MockTEEWorkloadPCR])
	if cert.Subject.CommonName != attested {
		t.Fatalf("certificate for %q, want the attested workload %q", cert.Subject.CommonName, attested)
	}
	roots, intermediates := x509.NewCertPool(), x509.NewCertPool()
	var chain []*x509.Certificate
	for rest := items[est.CredentialItemCACertsPEM]; len(rest) > 0; {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		c, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			t.Fatalf("CA chain: %v", err)
		}
		chain = append(chain, c)
	}
	if len(chain) == 0 {
		t.Fatal("bundle without a CA chain")
	}
	roots.AddCert(chain[len(chain)-1])
	for _, c := range chain[:len(chain)-1] {
		intermediates.AddCert(c)
	}
	if _, err := cert.Verify(x509.VerifyOptions{Roots: roots, Intermediates: intermediates}); err != nil {
		t.Fatalf("certificate does not verify under the bundle's CA chain: %v", err)
	}
	if !bytes.Equal(chain[0].Raw, f.issuer.Raw) {
		t.Fatal("the bundle's chain is not the mock CA's")
	}

	// the key: the private key of the certificate, able to sign
	parsed, err := x509.ParsePKCS8PrivateKey(items[est.CredentialItemPKCS8Key])
	if err != nil {
		t.Fatalf("private key: %v", err)
	}
	key, ok := parsed.(*ecdsa.PrivateKey)
	if !ok {
		t.Fatalf("private key of type %T, want ECDSA", parsed)
	}
	if !key.PublicKey.Equal(cert.PublicKey) {
		t.Fatal("the private key does not match the certificate's public key")
	}
	digest := sha256.Sum256([]byte(flowWorkloadCN))
	signature, err := ecdsa.SignASN1(rand.Reader, key, digest[:])
	if err != nil {
		t.Fatalf("signing with the released key: %v", err)
	}
	if !ecdsa.VerifyASN1(cert.PublicKey.(*ecdsa.PublicKey), digest[:], signature) {
		t.Fatal("a signature by the released key does not verify under the certificate")
	}

	// the metadata names the Target and the certificate's expiry
	if bundle.Metadata["target"] != flowRetrieveTarget(kind) {
		t.Fatalf("metadata target %q, want %q", bundle.Metadata["target"], flowRetrieveTarget(kind))
	}
	if bundle.Metadata["not_after"] != cert.NotAfter.UTC().Format(time.RFC3339) {
		t.Fatalf("metadata not_after %q, certificate expires %s", bundle.Metadata["not_after"], cert.NotAfter.UTC().Format(time.RFC3339))
	}

	// a replica of the workload is given the same credential
	again, _ := f.retrieveX509(t, kind, nil)
	if again.GroupID != bundle.GroupID {
		t.Fatalf("a replica got group %q, the first %q", again.GroupID, bundle.GroupID)
	}
	if !bytes.Equal(itemOf(again, est.CredentialItemX509Cert), cert.Raw) {
		t.Fatal("a replica got another certificate")
	}

	// another Credential Hint: another group, another certificate
	hint := flowHint
	hinted, _ := f.retrieveX509(t, kind, &hint)
	if hinted.GroupID == bundle.GroupID {
		t.Fatalf("the Credential Hint %q did not make a group of its own", hint)
	}
	if bytes.Equal(itemOf(hinted, est.CredentialItemX509Cert), cert.Raw) {
		t.Fatal("the hinted group got the first group's certificate")
	}
}

func itemOf(bundle *est.CredentialBundle, typ string) []byte {
	for _, item := range bundle.CredentialItems {
		if item.Type == typ {
			return item.Data
		}
	}
	return nil
}

// TestMockFlowPresentNonceHandleOnce: a present-nonce Handle serves one
// enrollment.
func TestMockFlowPresentNonceHandleOnce(t *testing.T) {
	f := newMockFlow(t)
	kind := est.FreshnessPresentNonce
	target := flowEnrollTarget(kind)
	csr := flowCSR(t, flowWorkloadCN)
	handle := f.handle(t, target, est.CredentialTypeX509, kind)
	if _, err := f.enroll(kind, handle, csr, f.evidence(t, kind, handle, target, csr)); err != nil {
		t.Fatalf("enrollment: %v", err)
	}
	_, err := f.enroll(kind, handle, csr, f.evidence(t, kind, handle, target, csr))
	requireRefusal(t, err, "replay")
}

// TestMockFlowAbsentTimestamp: the handle of absent-timestamp is the
// Attester's timestamp element, the one the Evidence binds and its issued-at
// repeats; Evidence older than the policy's window, a handle that is not the
// Evidence's timestamp, and a request without a handle are refused.
func TestMockFlowAbsentTimestamp(t *testing.T) {
	f := newMockFlow(t)
	kind := est.FreshnessAbsentTimestamp
	target := flowEnrollTarget(kind)
	csr := flowCSR(t, flowWorkloadCN)

	then := time.Now().Add(-flowStaleBy)
	stale, err := est.NewMockEvidenceAt(f.provider, kind, est.TimestampElement(then), target, csr, then)
	if err != nil {
		t.Fatalf("failed to create stale Evidence: %v", err)
	}
	_, err = f.enroll(kind, est.TimestampElement(then), csr, stale)
	requireRefusal(t, err, "stale")

	now := time.Now()
	evidence := f.evidence(t, kind, est.TimestampElement(now), target, csr)
	_, err = f.enroll(kind, est.TimestampElement(now.Add(time.Second)), csr, evidence)
	requireRefusal(t, err, "not bound")

	_, err = f.enroll(kind, nil, csr, evidence)
	requireRefusal(t, err, "no handle with absent-timestamp")

	if _, err := est.NewMockEvidence(f.provider, kind, nil, target, csr); err == nil {
		t.Fatal("mock Evidence of absent-timestamp made without a timestamp element")
	}
}
