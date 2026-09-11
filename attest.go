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

package est

import (
	"bytes"
	"context"
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/fxamacker/cbor/v2"
	"github.com/go-chi/chi"
	"github.com/veraison/eat"
	"github.com/veraison/go-cose"
)

// Freshness kinds carried in AttestationInitiateResponse.FreshnessKind.
const (
	// FreshnessPresentNonce is a single-use Handle originated by the Verifier
	// or Relying Party which the Attester must embed in Evidence.
	FreshnessPresentNonce = "present-nonce"

	// FreshnessAbsentNone carries no freshness claim. The EST client may
	// complete attest-initiate locally without contacting the EST server.
	FreshnessAbsentNone = "absent-none"
)

// Credential acquisition mechanisms returned by attest-initiate. These mirror
// caapi.v1.CredentialAcquisitionMechanism.
const (
	MechanismEnroll   = "enroll"   // OPERATION_ENROLL
	MechanismRetrieve = "retrieve" // OPERATION_RETRIEVE
)

// Credential types, mirroring caapi.v1.CredentialType. Bearer token types are
// acquired by retrieval; proof-of-possession types are acquired by enrollment.
const (
	CredentialTypeJWT    = "jwt"     // BT_CREDENTIAL_TYPE_JWT
	CredentialTypePSK    = "psk"     // BT_CREDENTIAL_TYPE_PSK
	CredentialTypeAPIKey = "api-key" // BT_CREDENTIAL_TYPE_API_KEY
	CredentialTypeX509   = "x509"    // POP_CREDENTIAL_TYPE_X509
	CredentialTypeWIC    = "wic"     // POP_CREDENTIAL_TYPE_WIC
	CredentialTypeWIT    = "wit"     // POP_CREDENTIAL_TYPE_WIT
)

// Request-level CSR and CEK association methods.
const (
	// BindingCSRHash identifies the enrollment request's CSR hash association.
	BindingCSRHash = "csr-hash"

	// BindingCEKThumbprint identifies the retrieval request's CEK association.
	BindingCEKThumbprint = "cek-thumbprint"
)

// EncECDHP256 is the authenticated-encryption suite used to encrypt an
// EncryptedCredentialBundle to CEKpub. It is a POC stand-in for the HPKE
// baseline the specification will ultimately mandate.
const EncECDHP256 = "ECDH-P256+HKDF-SHA256+A256GCM"

// Mock TEE evidence identifiers. These values define the non-production EAT
// profile appraised by the mock Verifier.
const (
	MockEATProfileURI   = "https://twi.confidentialcomputing.io/tacra-est-mock/1.0.0"
	MockEATMediaType    = "application/eat+cwt"
	MockEATProfileType  = `application/eat+cwt; eat_profile="` + MockEATProfileURI + `"`
	MockTEEType         = "mock-confidential-vm"
	MockTEEProviderID   = "twi-mock-tee-provider"
	MockTEESigningKeyID = "twi-mock-tee-key-1"
	MockTEEWorkloadPCR  = 4
	MockTEEPlatformPCR  = 0

	mockClaimPCRs          int64 = -70003
	mockClaimFreshnessKind int64 = -70004
)

// Credential item types carried inside an EncryptedCredentialBundle.
const (
	CredentialItemX509Cert   = "x509-cert"
	CredentialItemPKCS8Key   = "pkcs8-key"
	CredentialItemCACertsPEM = "ca-certs-pem"
)

// AttestationCA is an optional interface which a CA backing an EST server may
// implement in order to support attested credential acquisition. A backing CA
// which does not implement it is unaffected, and the attest-* endpoints will
// report that the operation is not implemented.
//
// The three operations correspond to the caapi.v1.CredentialAcquisitionService
// RPCs InitiateRemoteAttestation, EnrollCredential and RetrieveCredential.
type AttestationCA interface {
	// InitiateRemoteAttestation obtains a Freshness kind, and a Handle if any,
	// from the configured Verifier or Relying Party for the supplied target and
	// credential type. It also reports the credential acquisition mechanism.
	InitiateRemoteAttestation(ctx context.Context, target, credentialType, aps string, r *http.Request) (*AttestationInitiateResponse, error)

	// EnrollCredential forwards Evidence to the Verifier and the CSR plus the
	// resulting Attestation Results to the Credential Authority.
	EnrollCredential(ctx context.Context, req *AttestedEnrollmentRequest, aps string, r *http.Request) (*x509.Certificate, error)

	// RetrieveCredential forwards Evidence to the Verifier and the resulting
	// Attestation Results to the Secret Vault, which encrypts the matching
	// credential to CEKpub.
	RetrieveCredential(ctx context.Context, req *AttestedRetrievalRequest, aps string, r *http.Request) (*EncryptedCredentialBundle, error)
}

// AttestationInitiateResponse is returned by the attest-initiate resource. It
// carries the CAAPI InitiateCredentialAcquisitionResponse fields: Mechanism
// corresponds to mechanism, and Handle to the optional challenge.
type AttestationInitiateResponse struct {
	FreshnessKind      string   `json:"freshness_kind"`
	Handle             []byte   `json:"handle,omitempty"`
	ExpiresIn          int      `json:"expires_in,omitempty"`
	MaxAge             int      `json:"max_age,omitempty"`
	AcceptableEvidence []string `json:"acceptable_evidence,omitempty"`
	RequiredBindings   []string `json:"required_bindings,omitempty"`
	AcceptableCEK      []string `json:"acceptable_cek,omitempty"`
	Mechanism          string   `json:"mode,omitempty"`
}

// Binding declares the request-level CSR or CEK association method.
type Binding struct {
	Method  string `json:"method"`
	HashAlg string `json:"hash_alg,omitempty"`
}

// AttestedEnrollmentRequest is the attest-enroll request body.
type AttestedEnrollmentRequest struct {
	Target         string  `json:"target"`
	CredentialType string  `json:"credential_type,omitempty"`
	FreshnessKind  string  `json:"freshness_kind"`
	Handle         []byte  `json:"handle,omitempty"`
	CSR            []byte  `json:"csr"`
	Evidence       []byte  `json:"evidence"`
	Endorsements   []byte  `json:"endorsements,omitempty"`
	Binding        Binding `json:"binding"`
	Profile        string  `json:"profile,omitempty"`
}

// AttestedRetrievalRequest is the attest-retrieve request body.
type AttestedRetrievalRequest struct {
	Target         string  `json:"target"`
	CredentialType string  `json:"credential_type,omitempty"`
	FreshnessKind  string  `json:"freshness_kind"`
	Handle         []byte  `json:"handle,omitempty"`
	CEKPub         []byte  `json:"cek_pub"`
	Evidence       []byte  `json:"evidence"`
	Endorsements   []byte  `json:"endorsements,omitempty"`
	Binding        Binding `json:"binding"`
	Profile        string  `json:"profile,omitempty"`
}

// CredentialItem is a single credential inside a decrypted bundle.
type CredentialItem struct {
	Type string `json:"type"`
	Data []byte `json:"data"`
}

// CredentialBundle is the plaintext content of an EncryptedCredentialBundle.
type CredentialBundle struct {
	GroupID         string            `json:"group_id"`
	CredentialItems []CredentialItem  `json:"credential_items"`
	Metadata        map[string]string `json:"metadata,omitempty"`
}

// EncryptedCredentialBundle is an authenticated-encryption container encrypted
// to CEKpub. The EST server forwards it without being able to read it.
type EncryptedCredentialBundle struct {
	GroupID            string `json:"group_id"`
	Enc                string `json:"enc"`
	Profile            string `json:"profile,omitempty"`
	ServerID           string `json:"server_id,omitempty"`
	Handle             []byte `json:"handle,omitempty"`
	EphemeralPublicKey []byte `json:"epk"`
	Nonce              []byte `json:"nonce"`
	Ciphertext         []byte `json:"ciphertext"`
}

// MockEATClaims is the EAT claims set used by the non-production TEE profile.
// Request parameters such as target, CSR and CEKpub are deliberately absent.
type MockEATClaims struct {
	Issuer        string           `cbor:"1,keyasint,omitempty"`
	Subject       string           `cbor:"2,keyasint,omitempty"`
	IssuedAt      int64            `cbor:"6,keyasint,omitempty"`
	Nonce         *eat.Nonce       `cbor:"10,keyasint,omitempty"`
	UEID          eat.UEID         `cbor:"256,keyasint,omitempty"`
	HardwareModel []byte           `cbor:"259,keyasint,omitempty"`
	OemBoot       *bool            `cbor:"262,keyasint,omitempty"`
	DebugStatus   *eat.Debug       `cbor:"263,keyasint,omitempty"`
	Profile       *eat.Profile     `cbor:"265,keyasint,omitempty"`
	BootCount     *uint            `cbor:"267,keyasint,omitempty"`
	BootSeed      []byte           `cbor:"268,keyasint,omitempty"`
	SoftwareName  *eat.StringOrURI `cbor:"270,keyasint,omitempty"`
	PCRs          map[int][]byte   `cbor:"-70003,keyasint"`
	FreshnessKind string           `cbor:"-70004,keyasint"`
}

func mockPCRs() map[int][]byte {
	platform := sha256.Sum256([]byte("twi mock confidential platform v1"))
	workload := sha256.Sum256([]byte("twi-poc-workload"))

	return map[int][]byte{
		MockTEEPlatformPCR: platform[:],
		MockTEEWorkloadPCR: workload[:],
	}
}

// NewMockEvidence returns a CBOR COSE_Sign1 EAT signed by the supplied mock
// provider key. The provider retains ownership of the private key.
func NewMockEvidence(signer crypto.Signer, freshnessKind string, freshnessHandle []byte) ([]byte, error) {
	ecKey, ok := signer.(*ecdsa.PrivateKey)
	if !ok || ecKey.Curve != elliptic.P256() {
		return nil, fmt.Errorf("mock TEE signer must be an ECDSA P-256 private key")
	}

	profile, err := eat.NewProfile(MockEATProfileURI)
	if err != nil {
		return nil, fmt.Errorf("create mock EAT profile: %w", err)
	}
	var software eat.StringOrURI
	if err := software.FromString("twi-poc-workload"); err != nil {
		return nil, fmt.Errorf("create mock software claim: %w", err)
	}
	nonce := eat.Nonce{}
	switch freshnessKind {
	case FreshnessPresentNonce:
		if err := nonce.Add(freshnessHandle); err != nil {
			return nil, fmt.Errorf("create mock EAT nonce: %w", err)
		}
	case FreshnessAbsentNone:
		if len(freshnessHandle) != 0 {
			return nil, fmt.Errorf("freshness handle must be absent for absent-none")
		}
	default:
		return nil, fmt.Errorf("unsupported freshness kind %q", freshnessKind)
	}
	oemBoot := true
	debug := eat.Debug(eat.DebugDisabledSinceBoot)
	bootCount := uint(1)
	ueidHash := sha256.Sum256([]byte("twi mock TEE UEID v1"))
	ueid := append(eat.UEID{0x01}, ueidHash[:]...)
	bootSeed := sha256.Sum256([]byte("twi mock TEE boot seed v1"))
	claims := MockEATClaims{
		Issuer:        MockTEEProviderID,
		Subject:       "twi-poc-workload",
		IssuedAt:      time.Now().Unix(),
		UEID:          ueid,
		HardwareModel: []byte(MockTEEType),
		OemBoot:       &oemBoot,
		DebugStatus:   &debug,
		Profile:       profile,
		BootCount:     &bootCount,
		BootSeed:      bootSeed[:],
		SoftwareName:  &software,
		PCRs:          mockPCRs(),
		FreshnessKind: freshnessKind,
	}
	if freshnessKind == FreshnessPresentNonce {
		claims.Nonce = &nonce
	}
	payload, err := cbor.Marshal(claims)
	if err != nil {
		return nil, fmt.Errorf("encode mock EAT claims: %w", err)
	}
	coseSigner, err := cose.NewSigner(cose.AlgorithmES256, signer)
	if err != nil {
		return nil, fmt.Errorf("create mock COSE signer: %w", err)
	}
	headers := cose.Headers{
		Protected: cose.ProtectedHeader{
			cose.HeaderLabelAlgorithm:   cose.AlgorithmES256,
			cose.HeaderLabelContentType: MockEATMediaType,
		},
		Unprotected: cose.UnprotectedHeader{cose.HeaderLabelKeyID: []byte(MockTEESigningKeyID)},
	}
	return cose.Sign1(rand.Reader, coseSigner, headers, payload, nil)
}

// VerifyMockEvidence verifies the COSE signature and appraises the mock EAT
// profile and PCR measurements. Freshness correlation remains the caller's
// responsibility.
func VerifyMockEvidence(evidence []byte, providerKey crypto.PublicKey) (*MockEATClaims, error) {
	publicKey, ok := providerKey.(*ecdsa.PublicKey)
	if !ok || publicKey.Curve != elliptic.P256() {
		return nil, fmt.Errorf("trusted mock TEE key must be an ECDSA P-256 public key")
	}
	if len(evidence) == 0 || evidence[0] != 0xd2 {
		return nil, fmt.Errorf("mock evidence is not tagged COSE_Sign1")
	}
	var message cose.Sign1Message
	if err := message.UnmarshalCBOR(evidence); err != nil {
		return nil, fmt.Errorf("decode mock COSE_Sign1: %w", err)
	}
	if algorithm, ok := message.Headers.Protected[cose.HeaderLabelAlgorithm]; !ok || algorithm != cose.AlgorithmES256 {
		return nil, fmt.Errorf("mock COSE algorithm must be ES256")
	}
	if contentType, ok := message.Headers.Protected[cose.HeaderLabelContentType]; !ok || contentType != MockEATMediaType {
		return nil, fmt.Errorf("mock COSE content type must be %s", MockEATMediaType)
	}
	keyID, ok := message.Headers.Unprotected[cose.HeaderLabelKeyID].([]byte)
	if !ok || !bytes.Equal(keyID, []byte(MockTEESigningKeyID)) {
		return nil, fmt.Errorf("untrusted mock TEE signing key ID")
	}
	verifier, err := cose.NewVerifier(cose.AlgorithmES256, publicKey)
	if err != nil {
		return nil, fmt.Errorf("create mock COSE verifier: %w", err)
	}
	if err := message.Verify(nil, verifier); err != nil {
		return nil, fmt.Errorf("invalid mock TEE provider signature: %w", err)
	}
	var claims MockEATClaims
	if err := cbor.Unmarshal(message.Payload, &claims); err != nil {
		return nil, fmt.Errorf("decode mock EAT claims: %w", err)
	}
	if claims.Profile == nil {
		return nil, fmt.Errorf("mock EAT profile is missing")
	}
	profileURI, err := claims.Profile.Get()
	if err != nil {
		return nil, fmt.Errorf("decode mock EAT profile: %w", err)
	}
	if claims.Issuer != MockTEEProviderID ||
		claims.Subject != "twi-poc-workload" ||
		claims.IssuedAt <= 0 ||
		profileURI != MockEATProfileURI ||
		!bytes.Equal(claims.HardwareModel, []byte(MockTEEType)) ||
		claims.OemBoot == nil || !*claims.OemBoot ||
		claims.DebugStatus == nil || *claims.DebugStatus != eat.DebugDisabledSinceBoot ||
		claims.BootCount == nil || *claims.BootCount != 1 ||
		claims.SoftwareName == nil {
		return nil, fmt.Errorf("unsupported mock EAT profile")
	}
	if err := claims.UEID.Validate(); err != nil {
		return nil, fmt.Errorf("invalid mock EAT UEID: %w", err)
	}
	expectedBootSeed := sha256.Sum256([]byte("twi mock TEE boot seed v1"))
	if !bytes.Equal(claims.BootSeed, expectedBootSeed[:]) {
		return nil, fmt.Errorf("mock TEE boot seed policy mismatch")
	}

	expectedPCRs := mockPCRs()
	if len(claims.PCRs) != len(expectedPCRs) {
		return nil, fmt.Errorf("mock TEE PCR policy mismatch")
	}
	for register, expected := range expectedPCRs {
		if !bytes.Equal(claims.PCRs[register], expected) {
			return nil, fmt.Errorf("mock TEE PCR %d policy mismatch", register)
		}
	}

	return &claims, nil
}

// CSRHash returns the SHA-256 digest of a DER-encoded PKCS#10 CSR, for use as
// the csr-hash Evidence-to-CSR binding.
func CSRHash(csrDER []byte) []byte {
	sum := sha256.Sum256(csrDER)
	return sum[:]
}

// CEKThumbprint returns the SHA-256 thumbprint of an encoded CEK public key.
func CEKThumbprint(cekPub []byte) []byte {
	sum := sha256.Sum256(cekPub)
	return sum[:]
}

// bundleAAD builds the associated data binding the ciphertext to the group ID,
// Handle, profile and server identity.
func bundleAAD(groupID string, handle []byte, profile, serverID string) []byte {
	aad, _ := json.Marshal(struct {
		GroupID  string `json:"group_id"`
		Handle   []byte `json:"handle,omitempty"`
		Profile  string `json:"profile,omitempty"`
		ServerID string `json:"server_id,omitempty"`
	}{groupID, handle, profile, serverID})

	return aad
}

// SealCredentialBundle encrypts a credential bundle to an encoded P-256 CEK
// public key using ECDH, HKDF-SHA256 and AES-256-GCM.
func SealCredentialBundle(
	bundle *CredentialBundle,
	cekPub []byte,
	handle []byte,
	profile, serverID string,
) (*EncryptedCredentialBundle, error) {
	pub, err := ecdh.P256().NewPublicKey(cekPub)
	if err != nil {
		return nil, fmt.Errorf("invalid CEK public key: %w", err)
	}

	eph, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("failed to generate ephemeral key: %w", err)
	}

	shared, err := eph.ECDH(pub)
	if err != nil {
		return nil, fmt.Errorf("failed to compute shared secret: %w", err)
	}

	plaintext, err := json.Marshal(bundle)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal credential bundle: %w", err)
	}

	aad := bundleAAD(bundle.GroupID, handle, profile, serverID)

	key, err := hkdf.Key(sha256.New, shared, eph.PublicKey().Bytes(), string(aad), 32)
	if err != nil {
		return nil, fmt.Errorf("failed to derive content encryption key: %w", err)
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("failed to create AES cipher: %w", err)
	}

	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to create AES-GCM: %w", err)
	}

	nonce := make([]byte, aead.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, fmt.Errorf("failed to generate nonce: %w", err)
	}

	return &EncryptedCredentialBundle{
		GroupID:            bundle.GroupID,
		Enc:                EncECDHP256,
		Profile:            profile,
		ServerID:           serverID,
		Handle:             handle,
		EphemeralPublicKey: eph.PublicKey().Bytes(),
		Nonce:              nonce,
		Ciphertext:         aead.Seal(nil, nonce, plaintext, aad),
	}, nil
}

// Open decrypts an EncryptedCredentialBundle using the CEK private key. Only
// the holder of CEKpri can recover the credential, so the contents remain
// opaque to the EST client and EST server.
func (b *EncryptedCredentialBundle) Open(cekPriv *ecdh.PrivateKey) (*CredentialBundle, error) {
	if b.Enc != EncECDHP256 {
		return nil, fmt.Errorf("unsupported encryption suite %q", b.Enc)
	}

	epk, err := ecdh.P256().NewPublicKey(b.EphemeralPublicKey)
	if err != nil {
		return nil, fmt.Errorf("invalid ephemeral public key: %w", err)
	}

	shared, err := cekPriv.ECDH(epk)
	if err != nil {
		return nil, fmt.Errorf("failed to compute shared secret: %w", err)
	}

	aad := bundleAAD(b.GroupID, b.Handle, b.Profile, b.ServerID)

	key, err := hkdf.Key(sha256.New, shared, b.EphemeralPublicKey, string(aad), 32)
	if err != nil {
		return nil, fmt.Errorf("failed to derive content encryption key: %w", err)
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("failed to create AES cipher: %w", err)
	}

	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to create AES-GCM: %w", err)
	}

	plaintext, err := aead.Open(nil, b.Nonce, b.Ciphertext, aad)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt credential bundle: %w", err)
	}

	var bundle CredentialBundle
	if err := json.Unmarshal(plaintext, &bundle); err != nil {
		return nil, fmt.Errorf("failed to unmarshal credential bundle: %w", err)
	}

	return &bundle, nil
}

// attestationCAFromContext returns the backing CA as an AttestationCA, or nil
// if the backing CA does not support attested credential acquisition.
func attestationCAFromContext(ctx context.Context) AttestationCA {
	aca, _ := caFromContext(ctx).(AttestationCA)
	return aca
}

// decodeJSONRequest decodes a JSON request body, rejecting unknown fields.
func decodeJSONRequest(r *http.Request, v interface{}) error {
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()

	if err := dec.Decode(v); err != nil {
		return errInvalidJSON
	}

	return nil
}

// writeJSONResponse marshals and writes a JSON response body.
func writeJSONResponse(ctx context.Context, w http.ResponseWriter, v interface{}) {
	body, err := json.Marshal(v)
	if err != nil {
		LoggerFromContext(ctx).Errorf("failed to marshal JSON response: %v", err)
		errInternal.Write(w)
		return
	}

	writeResponse(w, mimeTypeJSON, false, body)
}

// attestInitiate services the /attest-initiate endpoint.
func attestInitiate(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	aps := chi.URLParam(r, apsParamName)

	aca := attestationCAFromContext(ctx)
	if aca == nil {
		errAttestNotSupported.Write(w)
		return
	}

	resp, err := aca.InitiateRemoteAttestation(
		ctx,
		r.URL.Query().Get(attestTargetParam),
		r.URL.Query().Get(attestCredentialTypeParam),
		aps,
		r,
	)
	if writeOnError(ctx, w, logMsgAttestInitiateFailed, err) {
		return
	}

	writeJSONResponse(ctx, w, resp)
}

// attestEnroll services the /attest-enroll endpoint.
func attestEnroll(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	aps := chi.URLParam(r, apsParamName)

	aca := attestationCAFromContext(ctx)
	if aca == nil {
		errAttestNotSupported.Write(w)
		return
	}

	var req AttestedEnrollmentRequest
	if err := decodeJSONRequest(r, &req); writeOnError(ctx, w, logMsgReadBodyFailed, err) {
		return
	}

	cert, err := aca.EnrollCredential(ctx, &req, aps, r)
	if writeOnError(ctx, w, logMsgAttestEnrollFailed, err) {
		return
	}

	writeResponse(w, mimeTypePKCS7CertsOnly, true, cert)
}

// attestRetrieve services the /attest-retrieve endpoint.
func attestRetrieve(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	aps := chi.URLParam(r, apsParamName)

	aca := attestationCAFromContext(ctx)
	if aca == nil {
		errAttestNotSupported.Write(w)
		return
	}

	var req AttestedRetrievalRequest
	if err := decodeJSONRequest(r, &req); writeOnError(ctx, w, logMsgReadBodyFailed, err) {
		return
	}

	bundle, err := aca.RetrieveCredential(ctx, &req, aps, r)
	if writeOnError(ctx, w, logMsgAttestRetrieveFailed, err) {
		return
	}

	writeJSONResponse(ctx, w, bundle)
}
