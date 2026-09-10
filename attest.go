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
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"net/http"

	"github.com/go-chi/chi"
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

// Evidence-to-CSR and Evidence-to-CEK binding methods.
const (
	// BindingCSRHash indicates Evidence contains H(csr_der).
	BindingCSRHash = "csr-hash"

	// BindingCEKThumbprint indicates Evidence contains a thumbprint of CEKpub.
	BindingCEKThumbprint = "cek-thumbprint"
)

// EncECDHP256 is the authenticated-encryption suite used to encrypt an
// EncryptedCredentialBundle to CEKpub. It is a POC stand-in for the HPKE
// baseline the specification will ultimately mandate.
const EncECDHP256 = "ECDH-P256+HKDF-SHA256+A256GCM"

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

// Binding declares how Evidence is bound to the CSR key or to CEKpub.
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

// MockEvidence is a non-production Evidence format used by this POC. Evidence
// is an opaque byte string at the protocol level; this structure is only the
// convention understood by the mock Verifier.
type MockEvidence struct {
	Target        string            `json:"target"`
	FreshnessKind string            `json:"freshness_kind"`
	Handle        []byte            `json:"handle,omitempty"`
	CSRHash       []byte            `json:"csr_hash,omitempty"`
	CEKPub        []byte            `json:"cek_pub,omitempty"`
	CEKThumbprint []byte            `json:"cek_thumbprint,omitempty"`
	Claims        map[string]string `json:"claims,omitempty"`
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
