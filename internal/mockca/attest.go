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
	"fmt"
	"io"
	"net/http"
	"slices"
	"strings"
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
	nonceLifetime       = time.Second * 300
	nonceSize           = 32
	defaultTimestampAge = 300
	trustedClockSkew    = 5 * time.Second
)

// nonceState tracks an issued present-nonce Handle.
type nonceState struct {
	target         string
	credentialType string
	credentialHint string
	expires        time.Time
	used           bool
}

// TargetPolicy is the CAS policy for one RATS-unaware Relying Party. Per TACRA
// the CAS — not the Attester and not the credential type — decides the
// credential acquisition mechanism, and it may differ per target.
type TargetPolicy struct {
	Name          string `json:"name"`
	Mechanism     string `json:"mechanism"`
	FreshnessKind string `json:"freshness_kind,omitempty"`
	EpochMarker   string `json:"epoch_marker,omitempty"`
	MaxAge        int    `json:"max_age,omitempty"`

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
		// A target the EST Server does not serve is a resource it does not have: the query is part of the target URI
		// (RFC 9110, Section 7.1), so 404.
		return TargetPolicy{}, caError{
			status: http.StatusNotFound,
			desc:   fmt.Sprintf("target %q is not supported", target),
		}
	}

	if credentialType != "" && !est.KnownCredentialType(credentialType) {
		// A credential type the profile does not define is a malformed request: 400.
		return TargetPolicy{}, caError{
			status: http.StatusBadRequest,
			desc:   fmt.Sprintf("credential type %q is not one the profile defines", credentialType),
		}
	}
	return policy, nil
}

// supportsType refuses a Credential Type the Target's policy does not list: 422, the body naming the ones it
// supports. At attest-initiate it is checked at once; on the second leg only after the Evidence was appraised, so
// that a failed attestation is refused with 403 whatever the Credential Type.
func supportsType(policy TargetPolicy, target, credentialType string) error {
	if credentialType == "" || len(policy.CredentialTypes) == 0 || slices.Contains(policy.CredentialTypes, credentialType) {
		return nil
	}
	return caError{
		status: http.StatusUnprocessableEntity,
		desc: fmt.Sprintf("credential type %q is not supported for target %q; supported: %s",
			credentialType, target, strings.Join(policy.CredentialTypes, ", ")),
	}
}

// requireMechanism rejects a second-leg request to the resource of the other
// mode: a Target the CAS provisions by retrieve is supported by a Secret Vault, one
// it provisions by enroll by a Credential Authority, and a request to the other
// resource is refused with 400.
func (ca *AttestedCA) requireMechanism(target, credentialType, requested string) error {
	policy, err := ca.policyFor(target, credentialType)
	if err != nil {
		return err
	}

	if policy.Mechanism != requested {
		return caError{
			status: http.StatusBadRequest,
			desc:   fmt.Sprintf("target %q is provisioned by %s, not %s", target, policy.Mechanism, requested),
		}
	}

	return nil
}

func policyFreshnessKind(policy TargetPolicy) string {
	if policy.FreshnessKind == "" {
		return est.FreshnessPresentNonce
	}
	return policy.FreshnessKind
}

func policyMaxAge(policy TargetPolicy) int {
	if policy.MaxAge > 0 {
		return policy.MaxAge
	}
	return defaultTimestampAge
}

// InitiateRemoteAttestation acts as a conduit to the mock Verifier or Relying
// Party that selects freshness. The mechanism and freshness policy are
// decided per target by the CAS, opaquely to the Attester.
func (ca *AttestedCA) InitiateRemoteAttestation(
	ctx context.Context,
	target, credentialType, credentialHint, additionalPathSegment string,
	r *http.Request,
) (*est.AttestationInitiateResponse, error) {
	policy, err := ca.policyFor(target, credentialType)
	if err != nil {
		return nil, err
	}
	// at attest-initiate there is no Evidence yet: the Credential Type is checked at once
	if err := supportsType(policy, target, credentialType); err != nil {
		return nil, err
	}

	mechanism := policy.Mechanism
	freshnessKind := policyFreshnessKind(policy)

	resp := &est.AttestationInitiateResponse{
		FreshnessKind:      freshnessKind,
		AcceptableEvidence: []string{est.MockEATProfileType},
		Mechanism:          mechanism,
	}

	switch freshnessKind {
	case est.FreshnessPresentNonce:
		handle := make([]byte, nonceSize)
		if _, err := io.ReadFull(rand.Reader, handle); err != nil {
			return nil, fmt.Errorf("failed to generate nonce: %w", err)
		}

		ca.mu.Lock()
		ca.nonces[hex.EncodeToString(handle)] = &nonceState{
			target:         target,
			credentialType: credentialType,
			credentialHint: credentialHint,
			expires:        time.Now().Add(nonceLifetime),
		}
		ca.mu.Unlock()

		resp.Handle = handle
		resp.ExpiresIn = int(nonceLifetime.Seconds())

	case est.FreshnessPresentEpoch:
		if policy.EpochMarker == "" {
			return nil, caError{status: http.StatusInternalServerError, desc: "present-epoch target has no epoch marker"}
		}
		resp.Handle = []byte(policy.EpochMarker)

	case est.FreshnessAbsentTimestamp:
		resp.MaxAge = policyMaxAge(policy)

	case est.FreshnessAbsentEpoch:
		if policy.EpochMarker == "" {
			return nil, caError{status: http.StatusInternalServerError, desc: "absent-epoch target has no epoch marker"}
		}

	case est.FreshnessAbsentNone:
		// No freshness parameters are returned.

	default:
		return nil, caError{
			status: http.StatusInternalServerError,
			desc:   fmt.Sprintf("target has unsupported freshness kind %q", freshnessKind),
		}
	}

	if mechanism == est.MechanismRetrieve {
		resp.AcceptableCEK = []string{est.AcceptableCEKMLKEM768P256, est.AcceptableCEKDHKEMP256}
	} else {
		resp.AcceptableCSK = []string{est.SigECDSAP256SHA256}
	}

	return resp, nil
}

// consumeHandle validates and burns a present-nonce Handle. A replayed, expired or
// never issued Handle yields 400 Bad Request.
func (ca *AttestedCA) consumeHandle(target, credentialType, credentialHint string, handle []byte) error {
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
		return caError{status: http.StatusBadRequest, desc: "unknown handle"}
	}
	if state.used {
		return caError{status: http.StatusBadRequest, desc: "handle replay detected"}
	}
	if time.Now().After(state.expires) {
		return caError{status: http.StatusBadRequest, desc: "handle has expired"}
	}
	if state.target != target {
		return caError{
			status: http.StatusBadRequest,
			desc:   "handle was not issued for this target",
		}
	}
	if state.credentialType != "" && state.credentialType != credentialType {
		// A credential type attest-initiate named must come back on the second leg; one it omitted may be named.
		return caError{
			status: http.StatusBadRequest,
			desc:   fmt.Sprintf("handle was issued for credential type %q", state.credentialType),
		}
	}
	if state.credentialHint != "" && state.credentialHint != credentialHint {
		// A Credential Hint attest-initiate named must come back on the second leg; one it omitted may be named.
		return caError{
			status: http.StatusBadRequest,
			desc:   fmt.Sprintf("handle was issued for credential hint %q", state.credentialHint),
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
// PCR policy, binding to the Freshness from attest-initiate, and the direct-
// form binding_input digest ({{binding-input}}) covering the Target and the
// subject (CSR or CEKpub), then returns Attestation Results.
func (ca *AttestedCA) verifyEvidence(
	target, credentialType, credentialHint, freshnessKind string,
	handle []byte,
	evidence []byte,
	subject []byte,
) (*attestationResults, error) {
	policy, err := ca.policyFor(target, credentialType)
	if err != nil {
		return nil, err
	}
	expectedFreshnessKind := policyFreshnessKind(policy)
	if freshnessKind != expectedFreshnessKind {
		return nil, caError{
			status: http.StatusBadRequest,
			desc:   "freshness kind does not match target policy",
		}
	}

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
			status: http.StatusBadRequest,
			desc:   "attestation failed: evidence freshness kind mismatch",
		}
	}

	switch freshnessKind {
	case est.FreshnessPresentNonce:
		if claims.Nonce == nil || claims.Nonce.Len() != 1 ||
			!bytes.Equal(claims.Nonce.GetI(0), handle) {
			return nil, caError{
				status: http.StatusBadRequest,
				desc:   "attestation failed: evidence not bound to handle",
			}
		}
		if err := ca.consumeHandle(target, credentialType, credentialHint, handle); err != nil {
			return nil, err
		}

	case est.FreshnessPresentEpoch, est.FreshnessAbsentEpoch:
		if len(handle) == 0 || claims.Nonce == nil || claims.Nonce.Len() != 1 ||
			!bytes.Equal(claims.Nonce.GetI(0), handle) {
			return nil, caError{
				status: http.StatusBadRequest,
				desc:   "attestation failed: evidence not bound to epoch marker",
			}
		}
		if !bytes.Equal(handle, []byte(policy.EpochMarker)) {
			return nil, caError{
				status: http.StatusBadRequest,
				desc:   "epoch marker has moved",
			}
		}

	case est.FreshnessAbsentTimestamp:
		// The handle is the Attester's timestamp element, which the Evidence
		// binds and whose instant its issued-at claim repeats; the age is
		// judged by this Verifier's clock.
		if claims.Nonce != nil {
			return nil, caError{
				status: http.StatusBadRequest,
				desc:   "a nonce claim with absent-timestamp freshness",
			}
		}
		stamped, err := est.TimestampFromElement(handle)
		if err != nil {
			return nil, caError{
				status: http.StatusBadRequest,
				desc:   fmt.Sprintf("handle must be the timestamp element for absent-timestamp freshness: %v", err),
			}
		}
		issuedAt := time.Unix(claims.IssuedAt, 0)
		if !stamped.Equal(issuedAt) {
			return nil, caError{
				status: http.StatusBadRequest,
				desc:   "attestation failed: evidence not bound to its timestamp",
			}
		}
		now := time.Now()
		if issuedAt.After(now.Add(trustedClockSkew)) {
			return nil, caError{
				status: http.StatusForbidden,
				desc:   "attestation failed: evidence timestamp is in the future",
			}
		}
		if now.Sub(issuedAt) > time.Duration(policyMaxAge(policy))*time.Second {
			return nil, caError{
				status: http.StatusForbidden,
				desc:   "attestation failed: evidence timestamp is stale",
			}
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

	// Evidence-to-Target and Evidence-to-CSR/CEK binding, recomputed here rather
	// than trusting the request; no server identity.
	expectedDigest := est.BindingDigest(handle, target, subject)
	if !bytes.Equal(claims.BindingDigest, expectedDigest) {
		return nil, caError{
			status: http.StatusBadRequest,
			desc:   "attestation failed: evidence not bound to this server, target or key material",
		}
	}

	// VerifyMockEvidence accepts the one issuer est.MockTEEProviderID, which has
	// no ":", and hex has none, so issuer and PCR are recoverable from Subject;
	// should that guarantee ever change, the construction refuses rather than
	// produce an ambiguous Subject.
	if strings.ContainsRune(claims.Issuer, ':') {
		return nil, caError{status: http.StatusInternalServerError, desc: "attestation failed: issuer contains ':'"}
	}
	subjectHex := hex.EncodeToString(claims.PCRs[est.MockTEEWorkloadPCR])

	return &attestationResults{
		Subject:       claims.Issuer + ":" + subjectHex,
		Target:        target,
		PolicyVersion: attestPolicyVersion,
	}, nil
}

// EnrollCredential forwards Evidence to the mock Verifier, then the CSR and
// Attestation Results to the mock Credential Authority.
func (ca *AttestedCA) EnrollCredential(
	ctx context.Context,
	req *est.AttestedEnrollmentRequest,
	additionalPathSegment string,
	r *http.Request,
) (*x509.Certificate, error) {
	if err := ca.requireMechanism(req.Target, req.CredentialType, est.MechanismEnroll); err != nil {
		return nil, err
	}
	if req.CredentialType != "" && !est.KnownCredentialType(req.CredentialType) {
		return nil, caError{status: http.StatusBadRequest, desc: fmt.Sprintf("credential type %q is not one the profile defines", req.CredentialType)}
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

	if req.Binding.Method != est.BindingInput {
		return nil, caError{status: http.StatusBadRequest, desc: "unsupported enrollment binding method"}
	}

	if _, err := ca.verifyEvidence(
		req.Target, req.CredentialType, hintOf(req.CredentialHint), req.FreshnessKind, req.Handle, req.Evidence, req.CSR,
	); err != nil {
		return nil, err
	}

	// The Credential Type after the attestation: a request that failed attestation is refused with 403 whatever it
	// asked for; one that passed and asks for a type this Credential Authority does not mint is refused with 422.
	policy, err := ca.policyFor(req.Target, req.CredentialType)
	if err != nil {
		return nil, err
	}
	if err := supportsType(policy, req.Target, req.CredentialType); err != nil {
		return nil, err
	}
	switch req.CredentialType {
	case "", est.CredentialTypeX509:
	case est.CredentialTypeWIC:
		return nil, caError{status: http.StatusUnprocessableEntity, desc: "wic is not minted by this mock yet; supported: x509"}
	default:
		return nil, caError{status: http.StatusUnprocessableEntity, desc: fmt.Sprintf("credential type %q is not minted by enrollment; supported: x509", req.CredentialType)}
	}

	return ca.MockCA.Enroll(ctx, csr, additionalPathSegment, r)
}

// groupID maps Attestation Results onto a credential group identifier which is
// stable across replica workloads and distinct across profiles and Credential
// Hints, per the profile's group_id = H(attestation_subject || credential_hint
// || policy_version) construction.
func groupID(res *attestationResults, profile, credentialHint string) string {
	h := sha256.New()
	h.Write([]byte(res.Subject))
	h.Write([]byte{0})
	h.Write([]byte(profile))
	h.Write([]byte{0})
	h.Write([]byte(credentialHint))
	h.Write([]byte{0})
	h.Write([]byte(res.PolicyVersion))

	return hex.EncodeToString(h.Sum(nil))
}

// vaultBundle returns the pre-provisioned credential of credentialType for a group, minting it on first use. Replica
// workloads sharing a group receive the same credential. The mock Secret Vault releases x509 (the certificate, its
// private key as a private-key item, and the CA chain as x509 items with the purpose "ca"), api-key (a hex token) and
// psk (32 key octets); a request that names another credential type is refused with 422, and one that names none is
// given x509, the policy of this mock. Every value is the unpadded base64url of the credential's octets.
func (ca *AttestedCA) vaultBundle(
	ctx context.Context,
	gid string,
	credentialType string,
	res *attestationResults,
	additionalPathSegment string,
	r *http.Request,
) (*est.CredentialBundle, error) {
	if credentialType == "" {
		credentialType = est.CredentialTypeX509
	}
	cacheKey := gid + "|" + credentialType
	ca.mu.Lock()
	if bundle, ok := ca.groups[cacheKey]; ok {
		ca.mu.Unlock()
		return bundle, nil
	}
	ca.mu.Unlock()

	switch credentialType {
	case est.CredentialTypeX509:
	case est.CredentialTypeAPIKey, est.CredentialTypePSK:
		secret := make([]byte, 32)
		if _, err := rand.Read(secret); err != nil {
			return nil, fmt.Errorf("failed to generate a group secret: %w", err)
		}
		if credentialType == est.CredentialTypeAPIKey {
			secret = []byte(hex.EncodeToString(secret)) // an API key is a token: its value carries the token's UTF-8
		}
		bundle := &est.CredentialBundle{
			CredentialItems: []est.CredentialItem{est.NewCredentialItem(credentialType, secret)},
			Metadata:        map[string]any{"policy_version": res.PolicyVersion, "target": res.Target},
		}
		ca.mu.Lock()
		if existing, ok := ca.groups[cacheKey]; ok {
			bundle = existing
		} else {
			ca.groups[cacheKey] = bundle
		}
		ca.mu.Unlock()
		return bundle, nil
	default:
		if !est.KnownCredentialType(credentialType) {
			return nil, caError{status: http.StatusBadRequest, desc: fmt.Sprintf("credential type %q is not one the profile defines", credentialType)}
		}
		return nil, caError{
			status: http.StatusUnprocessableEntity,
			desc:   fmt.Sprintf("credential type %q is not released by this Secret Vault; supported: x509, api-key, psk", credentialType),
		}
	}

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

	cert, err := ca.MockCA.Enroll(ctx, csr, additionalPathSegment, r)
	if err != nil {
		return nil, err
	}

	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal group key: %w", err)
	}

	cacerts, err := ca.MockCA.CACerts(ctx, additionalPathSegment, r)
	if err != nil {
		return nil, err
	}

	items := []est.CredentialItem{
		est.NewCredentialItem(est.CredentialTypeX509, cert.Raw),
		est.NewCredentialItem(est.CredentialTypePrivateKey, keyDER),
	}
	for _, c := range cacerts {
		ca := est.NewCredentialItem(est.CredentialTypeX509, c.Raw)
		ca.Purpose = []string{"ca"}
		items = append(items, ca)
	}

	bundle := &est.CredentialBundle{
		CredentialItems: items,
		Metadata: map[string]any{
			"not_after":      cert.NotAfter.UTC().Format(time.RFC3339),
			"policy_version": res.PolicyVersion,
			"target":         res.Target,
		},
	}

	ca.mu.Lock()
	if existing, ok := ca.groups[cacheKey]; ok {
		bundle = existing
	} else {
		ca.groups[cacheKey] = bundle
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
	additionalPathSegment string,
	r *http.Request,
) (*est.EncryptedCredentialBundle, error) {
	if err := ca.requireMechanism(req.Target, req.CredentialType, est.MechanismRetrieve); err != nil {
		return nil, err
	}

	if len(req.CEKPub) == 0 {
		return nil, caError{status: http.StatusBadRequest, desc: "CEKpub is required"}
	}
	if req.Binding.Method != est.BindingInput {
		return nil, caError{status: http.StatusBadRequest, desc: "unsupported retrieval binding method"}
	}

	res, err := ca.verifyEvidence(
		req.Target, req.CredentialType, hintOf(req.CredentialHint), req.FreshnessKind, req.Handle, req.Evidence, req.CEKPub,
	)
	if err != nil {
		return nil, err
	}

	// the Credential Type after the attestation, as at enrollment
	policy, err := ca.policyFor(req.Target, req.CredentialType)
	if err != nil {
		return nil, err
	}
	if err := supportsType(policy, req.Target, req.CredentialType); err != nil {
		return nil, err
	}

	var credentialHint string
	if req.CredentialHint != nil {
		credentialHint = *req.CredentialHint
	}

	gid := groupID(res, req.Profile, credentialHint)

	bundle, err := ca.vaultBundle(ctx, gid, req.CredentialType, res, additionalPathSegment, r)
	if err != nil {
		return nil, err
	}

	sealed, err := est.SealCredentialBundle(bundle, gid, req.CEKPub, req.Handle, req.Target, credentialHint)
	if err != nil {
		return nil, caError{
			status: http.StatusBadRequest,
			desc:   fmt.Sprintf("failed to encrypt credential bundle: %v", err),
		}
	}

	return sealed, nil
}

// hintOf is the Credential Hint of a second-leg request, or the empty string when the request carries none.
func hintOf(h *string) string {
	if h == nil {
		return ""
	}
	return *h
}
