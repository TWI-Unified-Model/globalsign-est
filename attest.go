package est

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/fxamacker/cbor/v2"
	"github.com/go-chi/chi/v5"
	"github.com/veraison/eat"
	"github.com/veraison/go-cose"
)

// Freshness kinds carried in AttestationInitiateResponse.FreshnessKind.
const (
	// FreshnessAbsentTimestamp uses the Attester's trusted clock. Evidence has
	// no Handle and its issued-at claim is checked against the configured
	// maximum age.
	FreshnessAbsentTimestamp = "absent-timestamp"

	// FreshnessAbsentNone carries no freshness claim. The EST client may
	// complete attest-initiate locally without contacting the EST server.
	FreshnessAbsentNone = "absent-none"

	// FreshnessAbsentEpoch uses an epoch marker already held by the Attester.
	// Initiation returns no Handle, but the marker is carried in the second-leg
	// Handle field and embedded in Evidence.
	FreshnessAbsentEpoch = "absent-epoch"

	// FreshnessPresentNonce is a single-use Handle originated by the Verifier
	// or Relying Party which the Attester must embed in Evidence.
	FreshnessPresentNonce = "present-nonce"

	// FreshnessPresentEpoch is the current epoch marker returned by the
	// Verifier or Relying Party and embedded by the Attester in Evidence.
	FreshnessPresentEpoch = "present-epoch"
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
	// BindingInput identifies the direct-form binding of TACRA's Section
	// "Binding Credential Keys to Evidence": a single digest, carried in a
	// guest-chosen Evidence field, over the freshness element, Target, RRP
	// identifier and CSR/CEKpub (internal/tacra/binding.go). It is the method
	// the attested requests name (Binding.Method).
	BindingInput = "binding-input"

	// BindingCSRHash identifies the enrollment request's CSR hash association.
	// Retained for documentation only: it binds Evidence to the CSR but not
	// to the Target, so this mock no longer accepts it alone.
	BindingCSRHash = "csr-hash"

	// BindingCEKThumbprint identifies the retrieval request's CEK association.
	// Retained for documentation only; see BindingCSRHash.
	BindingCEKThumbprint = "cek-thumbprint"
)

// SigECDSAP256SHA256 is the CSK signature algorithm an attest-initiate response
// offers for Enrollment (acceptable_csk).
const SigECDSAP256SHA256 = "ecdsa-p256-sha256"

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
	mockClaimBindingDigest int64 = -70005
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
// corresponds to mechanism, and Handle to the optional challenge. It names no
// RATS Relying Party: the Attester binds the identifier it holds for the
// Target and mode, never one from the CAS (TACRA, "Binding Credential Keys to
// Evidence").
type AttestationInitiateResponse struct {
	FreshnessKind      string   `json:"freshness_kind"`
	Handle             B64URL   `json:"handle,omitempty"`
	ExpiresIn          int      `json:"expires_in,omitempty"`
	MaxAge             int      `json:"max_age,omitempty"`
	AcceptableEvidence []string `json:"acceptable_evidence,omitempty"`
	AcceptableCSK      []string `json:"acceptable_csk,omitempty"`
	AcceptableCEK      []string `json:"acceptable_cek,omitempty"`
	Mechanism          string   `json:"mode,omitempty"`
}

// Binding declares the request-level Evidence-to-CSR or Evidence-to-CEK
// association method. Hash names the digest algorithm when Method uses one;
// this mock always uses SHA-512 for BindingInput.
type Binding struct {
	Method string `json:"method"`
	Hash   string `json:"hash,omitempty"`
}

// AttestedEnrollmentRequest is the attest-enroll request body.
type AttestedEnrollmentRequest struct {
	Target         string  `json:"target"`
	CredentialType string  `json:"credential_type,omitempty"`
	FreshnessKind  string  `json:"freshness_kind"`
	Handle         B64URL  `json:"handle,omitempty"`
	CSR            B64URL  `json:"csr"`
	Evidence       B64URL  `json:"evidence"`
	Binding        Binding `json:"binding"`
	Profile        string  `json:"profile,omitempty"`
	CredentialHint *string `json:"credential_hint,omitempty"`
}

// AttestedRetrievalRequest is the attest-retrieve request body.
type AttestedRetrievalRequest struct {
	Target         string  `json:"target"`
	CredentialType string  `json:"credential_type,omitempty"`
	FreshnessKind  string  `json:"freshness_kind"`
	Handle         B64URL  `json:"handle,omitempty"`
	CEKPub         B64URL  `json:"cek_pub"`
	Evidence       B64URL  `json:"evidence"`
	Binding        Binding `json:"binding"`
	Profile        string  `json:"profile,omitempty"`
	CredentialHint *string `json:"credential_hint,omitempty"`
}

// CredentialItem is a single credential inside a decrypted bundle, the credential-item of the EST draft's CDDL: its
// type, its value as text, and the format of the octets the value carries ("der", "pkcs8" or "pem" here).
type CredentialItem struct {
	Type   string `json:"type"`
	Format string `json:"format,omitempty"`
	Value  string `json:"value"`
}

// NewCredentialItem is an item whose value is the unpadded base64url encoding of octets.
func NewCredentialItem(typ, format string, octets []byte) CredentialItem {
	return CredentialItem{Type: typ, Format: format, Value: base64.RawURLEncoding.EncodeToString(octets)}
}

// Bytes returns the octets an item's value carries.
func (it CredentialItem) Bytes() ([]byte, error) {
	return base64.RawURLEncoding.DecodeString(it.Value)
}

// CredentialBundle is the plaintext of an EncryptedCredentialBundle (attest_bundle.go): the credential items and
// their metadata. The credential group is in the container's associated data.
type CredentialBundle struct {
	CredentialItems []CredentialItem `json:"credential_items"`
	Metadata        map[string]any   `json:"metadata,omitempty"` // string keys, any value (validity_seconds is an integer)
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
	BindingDigest []byte           `cbor:"-70005,keyasint"`
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
// freshnessHandle is the freshness element the Evidence binds and the
// second-leg request carries as its handle: the Handle of attest-initiate for
// present-nonce and present-epoch, the epoch marker the Attester holds for
// absent-epoch, the timestamp element of the Attester's clock for
// absent-timestamp (TimestampElement), and nothing for absent-none. target is
// the value the Attester intends to bind, and subject is the CSR DER
// (enrollment) or CEKpub SubjectPublicKeyInfo DER (retrieval); all are folded
// into the direct-form binding_input digest of {{binding-input}}.
func NewMockEvidence(
	signer crypto.Signer,
	freshnessKind string,
	freshnessHandle []byte,
	target string,
	subject []byte,
) ([]byte, error) {
	// The issued-at time is the Attester's clock reading: for absent-timestamp
	// the one the freshness element encodes, so that the Evidence and the
	// request carry the same instant.
	issuedAt := time.Now()
	if freshnessKind == FreshnessAbsentTimestamp {
		stamped, err := TimestampFromElement(freshnessHandle)
		if err != nil {
			return nil, err
		}
		issuedAt = stamped
	}
	return NewMockEvidenceAt(
		signer, freshnessKind, freshnessHandle, target, subject, issuedAt,
	)
}

// NewMockEvidenceAt is NewMockEvidence with an explicit trusted-clock time.
// It exists so absent-timestamp freshness and its age boundaries can be tested
// deterministically; for absent-timestamp, freshnessHandle must be the
// timestamp element of issuedAt. Production Evidence generation must obtain
// this value from the Attester's trusted clock.
func NewMockEvidenceAt(
	signer crypto.Signer,
	freshnessKind string,
	freshnessHandle []byte,
	target string,
	subject []byte,
	issuedAt time.Time,
) ([]byte, error) {
	ecKey, ok := signer.(*ecdsa.PrivateKey)
	if !ok || ecKey.Curve != elliptic.P256() {
		return nil, fmt.Errorf("mock TEE signer must be an ECDSA P-256 private key")
	}
	if len(subject) == 0 {
		return nil, fmt.Errorf("subject (CSR or CEKpub DER) is required to compute the binding digest")
	}
	if issuedAt.IsZero() || issuedAt.Unix() <= 0 {
		return nil, fmt.Errorf("issued-at time is required")
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
	case FreshnessPresentNonce, FreshnessPresentEpoch, FreshnessAbsentEpoch:
		if len(freshnessHandle) == 0 {
			return nil, fmt.Errorf("freshness handle is required for %s", freshnessKind)
		}
		if err := nonce.Add(freshnessHandle); err != nil {
			return nil, fmt.Errorf("create mock EAT nonce: %w", err)
		}
	case FreshnessAbsentTimestamp:
		if !bytes.Equal(freshnessHandle, TimestampElement(issuedAt)) {
			return nil, fmt.Errorf("freshness handle must be the timestamp element of the issued-at time for %s", freshnessKind)
		}
	case FreshnessAbsentNone:
		if len(freshnessHandle) != 0 {
			return nil, fmt.Errorf("freshness handle must be absent for %s", freshnessKind)
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
		IssuedAt:      issuedAt.Unix(),
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
		BindingDigest: BindingDigest(freshnessHandle, target, subject),
	}
	if freshnessKind == FreshnessPresentNonce ||
		freshnessKind == FreshnessPresentEpoch ||
		freshnessKind == FreshnessAbsentEpoch {
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

// TimestampElementSize is the length in octets of the absent-timestamp
// freshness element.
const TimestampElementSize = 8

// TimestampElement is the absent-timestamp freshness element of t: seconds
// since 1970-01-01T00:00:00Z as an 8-octet big-endian unsigned integer, the
// encoding TACRA's binding gives the Attester's timestamp. The Attester binds
// it in Evidence and carries it as the handle of attest-enroll and
// attest-retrieve, since the Evidence of a hardware TEE carries no clock
// reading of its own.
func TimestampElement(t time.Time) []byte {
	return binary.BigEndian.AppendUint64(nil, uint64(t.Unix()))
}

// TimestampFromElement is the time an absent-timestamp freshness element
// encodes.
func TimestampFromElement(element []byte) (time.Time, error) {
	if len(element) != TimestampElementSize {
		return time.Time{}, fmt.Errorf(
			"absent-timestamp freshness element: %d octets, not %d", len(element), TimestampElementSize,
		)
	}
	return time.Unix(int64(binary.BigEndian.Uint64(element)), 0), nil
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

// EncodeBindingInput returns the canonical octet string of the mock's binding
// input: length-prefixed handle, target and subject, where each length is a
// 32-bit big-endian octet count (no server identity since 6 October 2026,
// rats-tacra#20; the TACRA backend keeps Section 4.5's own layout). handle is
// empty for absent-none/absent-timestamp; subject is the CSR DER for
// enrollment or the CEKpub SubjectPublicKeyInfo DER for retrieval. The length
// prefixes make the concatenation unambiguous.
func EncodeBindingInput(handle []byte, target string, subject []byte) []byte {
	var buf bytes.Buffer
	for _, part := range [][]byte{handle, []byte(target), subject} {
		var length [4]byte
		binary.BigEndian.PutUint32(length[:], uint32(len(part)))
		buf.Write(length[:])
		buf.Write(part)
	}
	return buf.Bytes()
}

// BindingDigest returns the SHA-512 digest of EncodeBindingInput, matching the
// direct platform form for a 64-octet report-data field (e.g. AMD SEV-SNP
// REPORT_DATA or Intel TDX REPORTDATA).
func BindingDigest(handle []byte, target string, subject []byte) []byte {
	sum := sha512.Sum512(EncodeBindingInput(handle, target, subject))
	return sum[:]
}

// attestationCAFromContext returns the backing CA as an AttestationCA, or nil
// if the backing CA does not support attested credential acquisition.
func attestationCAFromContext(ctx context.Context) AttestationCA {
	aca, _ := caFromContext(ctx).(AttestationCA)
	return aca
}

// writeJSONResponse marshals and writes a JSON response body of the given media
// type.
func writeJSONResponse(ctx context.Context, w http.ResponseWriter, contentType string, v interface{}) {
	body, err := json.Marshal(v)
	if err != nil {
		LoggerFromContext(ctx).Errorf("failed to marshal JSON response: %v", err)
		errInternal.Write(w)
		return
	}

	writeResponse(w, contentType, false, body)
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

	writeJSONResponse(ctx, w, mimeTypeAttestInitiate, resp)
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
	if err := decodeAttestedRequest(r, "csr", &req); writeOnError(ctx, w, logMsgReadBodyFailed, err) {
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
	if err := decodeAttestedRequest(r, "cek_pub", &req); writeOnError(ctx, w, logMsgReadBodyFailed, err) {
		return
	}

	// A CA that forwards a container produced by its Secret Vault returns it as it is.
	if raw, ok := aca.(RawRetriever); ok {
		body, err := raw.RetrieveCredentialRaw(ctx, &req, aps, r)
		if writeOnError(ctx, w, logMsgAttestRetrieveFailed, err) {
			return
		}
		writeResponse(w, mimeTypeAttestBundle, false, body)
		return
	}

	bundle, err := aca.RetrieveCredential(ctx, &req, aps, r)
	if writeOnError(ctx, w, logMsgAttestRetrieveFailed, err) {
		return
	}

	writeJSONResponse(ctx, w, mimeTypeAttestBundle, bundle)
}

// RawRetriever is implemented by an AttestationCA whose Secret Vault produces the
// EncryptedCredentialBundle itself (for example the hpke-auth container of the
// revised EST profile): the EST server returns that container unchanged, as a
// conduit, instead of re-encoding it as the mock's container type.
type RawRetriever interface {
	RetrieveCredentialRaw(ctx context.Context, req *AttestedRetrievalRequest, aps string, r *http.Request) ([]byte, error)
}
