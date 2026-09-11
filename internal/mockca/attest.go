/*
Copyright (c) 2020 GMO GlobalSign, Inc.

Licensed under the MIT License (the "License"); you may not use this file except
in compliance with the License. You may obtain a copy of the License at

https://opensource.org/licenses/MIT

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package mockca

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"sync"
	"time"

	"github.com/globalsign/est"
)

// Attestation POC constants.
const (
	// DefaultEnrollTarget and DefaultRetrieveTarget are the RATS-unaware
	// Relying Parties configured when no explicit target policy is supplied.
	// Two are provided because TACRA Req 5 requires support for different
	// mechanisms per target.
	DefaultEnrollTarget   = "RUP-workload-1"
	DefaultRetrieveTarget = "RUP-workload-2"

	attestPolicyVersion = "poc-policy-v1"
	attestServerID      = "twi-globalsign-est"
	nonceLifetime       = time.Second * 300
	nonceSize           = 32
)

// nonceState tracks an issued present-nonce Handle.
type nonceState struct {
	target  string
	expires time.Time
	used    bool
}

// TargetPolicy is the CAS policy for one RATS-unaware Relying Party. Per TACRA
// the CAS — not the Attester and not the credential type — decides the
// credential acquisition mechanism, and it may differ per target.
type TargetPolicy struct {
	Name      string `json:"name"`
	Mechanism string `json:"mechanism"`

	// CredentialTypes optionally restricts which credential types the CAS can
	// provision for this target. An empty list accepts any type.
	CredentialTypes []string `json:"credential_types,omitempty"`
}

// AttestedCA extends MockCA with the attested credential acquisition
// operations defined by the TACRA EST extensions. It embeds MockCA so it
// continues to satisfy est.CA, and additionally satisfies est.AttestationCA.
//
// The Verifier, Credential Authority and Secret Vault are all mocked in
// process. This type is for testing purposes only.
type AttestedCA struct {
	*MockCA

	targets            map[string]TargetPolicy
	trustedProviderKey crypto.PublicKey

	mu     sync.Mutex
	nonces map[string]*nonceState
	groups map[string]*est.CredentialBundle
}

// NewAttested wraps a MockCA with mock attestation support. If targets is
// empty, a default enroll target and retrieve target are configured.
func NewAttested(ca *MockCA, targets []TargetPolicy, trustedProviderKey crypto.PublicKey) *AttestedCA {
	policies := make(map[string]TargetPolicy)
	for _, t := range targets {
		if t.Name == "" {
			continue
		}
		if t.Mechanism == "" {
			t.Mechanism = est.MechanismEnroll
		}
		policies[t.Name] = t
	}

	if len(policies) == 0 {
		policies[DefaultEnrollTarget] = TargetPolicy{
			Name:      DefaultEnrollTarget,
			Mechanism: est.MechanismEnroll,
		}
		policies[DefaultRetrieveTarget] = TargetPolicy{
			Name:      DefaultRetrieveTarget,
			Mechanism: est.MechanismRetrieve,
		}
	}

	return &AttestedCA{
		MockCA:             ca,
		targets:            policies,
		trustedProviderKey: trustedProviderKey,
		nonces:             make(map[string]*nonceState),
		groups:             make(map[string]*est.CredentialBundle),
	}
}

// AllowedTargets returns the configured target names.
func (ca *AttestedCA) AllowedTargets() []string {
	out := make([]string, 0, len(ca.targets))
	for t := range ca.targets {
		out = append(out, t)
	}
	return out
}

// policyFor enforces the target whitelist and validates that the CAS can
// provision the requested credential type for that target.
func (ca *AttestedCA) policyFor(target, credentialType string) (TargetPolicy, error) {
	if target == "" {
		return TargetPolicy{}, caError{status: http.StatusBadRequest, desc: "target is required"}
	}

	policy, ok := ca.targets[target]
	if !ok {
		return TargetPolicy{}, caError{
			status: http.StatusForbidden,
			desc:   fmt.Sprintf("target %q is not an allowed target", target),
		}
	}

	if credentialType != "" && len(policy.CredentialTypes) > 0 {
		supported := false
		for _, ct := range policy.CredentialTypes {
			if ct == credentialType {
				supported = true
				break
			}
		}
		if !supported {
			return TargetPolicy{}, caError{
				status: http.StatusForbidden,
				desc:   fmt.Sprintf("credential type %q is not available for target %q", credentialType, target),
			}
		}
	}

	return policy, nil
}

// requireMechanism rejects a second-leg request that does not match the
// mechanism the CAS selected for the target.
func (ca *AttestedCA) requireMechanism(target, credentialType, want string) error {
	policy, err := ca.policyFor(target, credentialType)
	if err != nil {
		return err
	}

	if policy.Mechanism != want {
		return caError{
			status: http.StatusForbidden,
			desc:   fmt.Sprintf("target %q requires the %s mechanism", target, policy.Mechanism),
		}
	}

	return nil
}

// InitiateRemoteAttestation acts as a conduit to the mock Verifier, which
// originates a single-use present-nonce Handle. The mechanism is decided here
// by the CAS, opaquely to the Attester.
func (ca *AttestedCA) InitiateRemoteAttestation(
	ctx context.Context,
	target, credentialType, aps string,
	r *http.Request,
) (*est.AttestationInitiateResponse, error) {
	policy, err := ca.policyFor(target, credentialType)
	if err != nil {
		return nil, err
	}

	handle := make([]byte, nonceSize)
	if _, err := io.ReadFull(rand.Reader, handle); err != nil {
		return nil, fmt.Errorf("failed to generate nonce: %w", err)
	}

	ca.mu.Lock()
	ca.nonces[hex.EncodeToString(handle)] = &nonceState{
		target:  target,
		expires: time.Now().Add(nonceLifetime),
	}
	ca.mu.Unlock()

	mechanism := policy.Mechanism

	resp := &est.AttestationInitiateResponse{
		FreshnessKind:      est.FreshnessPresentNonce,
		Handle:             handle,
		ExpiresIn:          int(nonceLifetime.Seconds()),
		AcceptableEvidence: []string{est.MockEATProfileType},
		Mechanism:          mechanism,
	}

	if mechanism == est.MechanismRetrieve {
		resp.RequiredBindings = []string{est.BindingCEKThumbprint}
		resp.AcceptableCEK = []string{est.EncECDHP256}
	} else {
		resp.RequiredBindings = []string{est.BindingCSRHash}
	}

	return resp, nil
}

// consumeHandle validates and burns a present-nonce Handle. A replayed or
// expired Handle yields 409 Conflict.
func (ca *AttestedCA) consumeHandle(target string, handle []byte) error {
	if len(handle) == 0 {
		return caError{
			status: http.StatusBadRequest,
			desc:   "handle is required for present-nonce freshness",
		}
	}

	ca.mu.Lock()
	defer ca.mu.Unlock()

	state, ok := ca.nonces[hex.EncodeToString(handle)]
	if !ok {
		return caError{status: http.StatusConflict, desc: "unknown handle"}
	}
	if state.used {
		return caError{status: http.StatusConflict, desc: "handle replay detected"}
	}
	if time.Now().After(state.expires) {
		return caError{status: http.StatusConflict, desc: "handle has expired"}
	}
	if state.target != target {
		return caError{
			status: http.StatusForbidden,
			desc:   "handle was not issued for this target",
		}
	}

	state.used = true

	return nil
}

// attestationResults is the mock Verifier's appraisal output. Only the
// Verifier produces it; the EST server forwards it without appraising.
type attestationResults struct {
	Subject       string
	Target        string
	PolicyVersion string
}

// verifyEvidence mocks the RATS Verifier. It validates the provider signature,
// PCR policy and binding to the Freshness from attest-initiate, then returns
// Attestation Results.
func (ca *AttestedCA) verifyEvidence(
	target, freshnessKind string,
	handle []byte,
	evidence []byte,
) (*attestationResults, error) {
	claims, err := est.VerifyMockEvidence(evidence, ca.trustedProviderKey)
	if err != nil {
		return nil, caError{
			status: http.StatusForbidden,
			desc:   fmt.Sprintf("attestation failed: %v", err),
		}
	}

	// Evidence-to-Freshness binding.
	if claims.FreshnessKind != freshnessKind {
		return nil, caError{
			status: http.StatusForbidden,
			desc:   "attestation failed: evidence freshness kind mismatch",
		}
	}

	switch freshnessKind {
	case est.FreshnessPresentNonce:
		if claims.Nonce == nil || claims.Nonce.Len() != 1 ||
			!bytes.Equal(claims.Nonce.GetI(0), handle) {
			return nil, caError{
				status: http.StatusForbidden,
				desc:   "attestation failed: evidence not bound to handle",
			}
		}
		if err := ca.consumeHandle(target, handle); err != nil {
			return nil, err
		}

	case est.FreshnessAbsentNone:
		if len(handle) != 0 || claims.Nonce != nil {
			return nil, caError{
				status: http.StatusBadRequest,
				desc:   "handle must be absent for absent-none freshness",
			}
		}

	default:
		return nil, caError{
			status: http.StatusBadRequest,
			desc:   fmt.Sprintf("unsupported freshness kind %q", freshnessKind),
		}
	}

	subject := claims.Issuer + ":" + hex.EncodeToString(claims.PCRs[est.MockTEEWorkloadPCR])

	return &attestationResults{
		Subject:       subject,
		Target:        target,
		PolicyVersion: attestPolicyVersion,
	}, nil
}

// EnrollCredential forwards Evidence to the mock Verifier, then the CSR and
// Attestation Results to the mock Credential Authority.
func (ca *AttestedCA) EnrollCredential(
	ctx context.Context,
	req *est.AttestedEnrollmentRequest,
	aps string,
	r *http.Request,
) (*x509.Certificate, error) {
	if err := ca.requireMechanism(req.Target, req.CredentialType, est.MechanismEnroll); err != nil {
		return nil, err
	}

	if len(req.CSR) == 0 {
		return nil, caError{status: http.StatusBadRequest, desc: "csr is required"}
	}

	csr, err := x509.ParseCertificateRequest(req.CSR)
	if err != nil {
		return nil, caError{status: http.StatusBadRequest, desc: "malformed PKCS10 certificate signing request"}
	}

	// The Credential Authority verifies proof of possession of the CSR key.
	if err := csr.CheckSignature(); err != nil {
		return nil, caError{status: http.StatusBadRequest, desc: "invalid PKCS10 certificate signing request signature"}
	}

	if req.Binding.Method != est.BindingCSRHash {
		return nil, caError{status: http.StatusBadRequest, desc: "unsupported enrollment binding method"}
	}

	if _, err := ca.verifyEvidence(
		req.Target, req.FreshnessKind, req.Handle, req.Evidence,
	); err != nil {
		return nil, err
	}

	return ca.MockCA.Enroll(ctx, csr, aps, r)
}

// groupID maps Attestation Results onto a credential group identifier which is
// stable across replica workloads and distinct across profiles.
func groupID(res *attestationResults, profile string) string {
	h := sha256.New()
	h.Write([]byte(res.Subject))
	h.Write([]byte{0})
	h.Write([]byte(profile))
	h.Write([]byte{0})
	h.Write([]byte(res.PolicyVersion))

	return hex.EncodeToString(h.Sum(nil))
}

// vaultBundle returns the pre-provisioned credential for a group, minting it
// on first use. Replica workloads sharing a group receive the same credential.
func (ca *AttestedCA) vaultBundle(
	ctx context.Context,
	gid string,
	res *attestationResults,
	aps string,
	r *http.Request,
) (*est.CredentialBundle, error) {
	ca.mu.Lock()
	if bundle, ok := ca.groups[gid]; ok {
		ca.mu.Unlock()
		return bundle, nil
	}
	ca.mu.Unlock()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("failed to generate group key: %w", err)
	}

	csrDER, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject: pkix.Name{CommonName: res.Subject},
	}, key)
	if err != nil {
		return nil, fmt.Errorf("failed to create group certificate request: %w", err)
	}

	csr, err := x509.ParseCertificateRequest(csrDER)
	if err != nil {
		return nil, fmt.Errorf("failed to parse group certificate request: %w", err)
	}

	cert, err := ca.MockCA.Enroll(ctx, csr, aps, r)
	if err != nil {
		return nil, err
	}

	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal group key: %w", err)
	}

	cacerts, err := ca.MockCA.CACerts(ctx, aps, r)
	if err != nil {
		return nil, err
	}

	var chain bytes.Buffer
	for _, c := range cacerts {
		if err := pem.Encode(&chain, &pem.Block{Type: "CERTIFICATE", Bytes: c.Raw}); err != nil {
			return nil, fmt.Errorf("failed to encode CA certificate: %w", err)
		}
	}

	bundle := &est.CredentialBundle{
		GroupID: gid,
		CredentialItems: []est.CredentialItem{
			{Type: est.CredentialItemX509Cert, Data: cert.Raw},
			{Type: est.CredentialItemPKCS8Key, Data: keyDER},
			{Type: est.CredentialItemCACertsPEM, Data: chain.Bytes()},
		},
		Metadata: map[string]string{
			"not_after":      cert.NotAfter.UTC().Format(time.RFC3339),
			"policy_version": res.PolicyVersion,
			"target":         res.Target,
		},
	}

	ca.mu.Lock()
	if existing, ok := ca.groups[gid]; ok {
		bundle = existing
	} else {
		ca.groups[gid] = bundle
	}
	ca.mu.Unlock()

	return bundle, nil
}

// RetrieveCredential forwards Evidence to the mock Verifier, then Attestation
// Results to the mock Secret Vault, which encrypts the credential to CEKpub.
// The EST server never sees the plaintext credential.
func (ca *AttestedCA) RetrieveCredential(
	ctx context.Context,
	req *est.AttestedRetrievalRequest,
	aps string,
	r *http.Request,
) (*est.EncryptedCredentialBundle, error) {
	if err := ca.requireMechanism(req.Target, req.CredentialType, est.MechanismRetrieve); err != nil {
		return nil, err
	}

	if len(req.CEKPub) == 0 {
		return nil, caError{status: http.StatusBadRequest, desc: "CEKpub is required"}
	}
	if req.Binding.Method != est.BindingCEKThumbprint {
		return nil, caError{status: http.StatusBadRequest, desc: "unsupported retrieval binding method"}
	}

	res, err := ca.verifyEvidence(
		req.Target, req.FreshnessKind, req.Handle, req.Evidence,
	)
	if err != nil {
		return nil, err
	}

	gid := groupID(res, req.Profile)

	bundle, err := ca.vaultBundle(ctx, gid, res, aps, r)
	if err != nil {
		return nil, err
	}

	sealed, err := est.SealCredentialBundle(bundle, req.CEKPub, req.Handle, req.Profile, attestServerID)
	if err != nil {
		return nil, caError{
			status: http.StatusBadRequest,
			desc:   fmt.Sprintf("failed to encrypt credential bundle: %v", err),
		}
	}

	return sealed, nil
}
