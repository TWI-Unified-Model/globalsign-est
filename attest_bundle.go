package est

// The EncryptedCredentialBundle of the EST profile (draft-novak-lamps-tacra-est, Response: EncryptedCredentialBundle;
// issue #15 of the draft, 28 and 29 October 2026), as TACRA's "Sealing the Released Credential" constructs it: HPKE in
// base mode (RFC 9180) to CEKpub, under one of two suites. The EST client and server saw CEKpub and could seal a
// container to it themselves: the profile accepts that risk, states it in its Security Considerations, and carries no
// origin authentication in this version.
//
//	suites        MLKEM768-P256 (HPKE KEM 0x0050, draft-ietf-hpke-pq) or DHKEM(P-256, HKDF-SHA256) (0x0010), each with
//	              HKDF-SHA256 (0x0001) and AES-256-GCM (0x0002); the suite follows the encoding of CEKpub
//	CEKpub        the 1249-octet MLKEM768-P256 encapsulation key, or the DER SubjectPublicKeyInfo of a P-256 key
//	info          len32-prefixed: "tacra hpke-base v1", the Target, the freshness element
//	aad           the JSON Canonicalization Scheme (RFC 8785) of {group_id, target, handle?, credential_hint?}
//	plaintext     the JCS of the CredentialBundle

import (
	"bytes"
	"crypto"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/hpke"
	"crypto/x509"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
)

// BundleContainer names the container of the EST profile.
const BundleContainer = "hpke-base"

// BundleSuite names the HPKE algorithms of a container, as its suite member carries them.
type BundleSuite struct {
	KEM  string `json:"kem"`
	KDF  string `json:"kdf"`
	AEAD string `json:"aead"`
}

// The two suites of the container, and their names in acceptable_cek.
var (
	BundleSuiteMLKEM768P256 = BundleSuite{KEM: "MLKEM768-P256", KDF: "HKDF-SHA256", AEAD: "AES-256-GCM"}
	BundleSuiteDHKEMP256    = BundleSuite{KEM: "DHKEM(P-256, HKDF-SHA256)", KDF: "HKDF-SHA256", AEAD: "AES-256-GCM"}
)

const (
	AcceptableCEKMLKEM768P256 = "MLKEM768-P256+HKDF-SHA256+AES-256-GCM"
	AcceptableCEKDHKEMP256    = "DHKEM(P-256, HKDF-SHA256)+HKDF-SHA256+AES-256-GCM"
)

// BundleAAD is the associated data of the container: what the Attester bound and the group the Secret Vault chose.
// Target carries the Target octets base64url, as TACRA-02 specifies, and the Attester compares the decoded octets.
type BundleAAD struct {
	GroupID        string `json:"group_id"`
	Target         B64URL `json:"target"`
	Handle         B64URL `json:"handle,omitempty"`
	CredentialHint string `json:"credential_hint,omitempty"`
}

// EncryptedCredentialBundle is the container the Secret Vault returns and the EST server forwards without reading it.
type EncryptedCredentialBundle struct {
	Container  string      `json:"container"`
	Suite      BundleSuite `json:"suite"`
	Enc        B64URL      `json:"enc"`
	Ciphertext B64URL      `json:"ciphertext"`
	AAD        BundleAAD   `json:"aad"`
}

const bundleInfoLabel = "tacra hpke-base v1"

type bundleSuite struct {
	suite BundleSuite
	kem   hpke.KEM
	id    []byte // the HPKE suite_id of RFC 9180 Section 5.1: "HPKE" || kem_id || kdf_id || aead_id
}

func bundleSuiteID(kemID uint16) []byte {
	return []byte{'H', 'P', 'K', 'E', byte(kemID >> 8), byte(kemID), 0x00, 0x01, 0x00, 0x02}
}

var bundleSuites = []bundleSuite{
	{suite: BundleSuiteMLKEM768P256, kem: hpke.MLKEM768P256(), id: bundleSuiteID(0x0050)},
	{suite: BundleSuiteDHKEMP256, kem: hpke.DHKEM(ecdh.P256()), id: bundleSuiteID(0x0010)},
}

func bundleKDFAEAD() (hpke.KDF, hpke.AEAD) {
	return hpke.HKDFSHA256(), hpke.AES256GCM()
}

// bundleSuiteOf reads CEKpub as the request carries it: an MLKEM768-P256 encapsulation key, else the DER
// SubjectPublicKeyInfo of a P-256 key.
func bundleSuiteOf(cekPub []byte) (bundleSuite, hpke.PublicKey, error) {
	if pk, err := bundleSuites[0].kem.NewPublicKey(cekPub); err == nil {
		return bundleSuites[0], pk, nil
	}
	if pub, err := x509.ParsePKIXPublicKey(cekPub); err == nil {
		var e *ecdh.PublicKey
		switch k := pub.(type) {
		case *ecdsa.PublicKey:
			if k.Curve == elliptic.P256() {
				e, _ = k.ECDH()
			}
		case *ecdh.PublicKey:
			if k.Curve() == ecdh.P256() {
				e = k
			}
		}
		if e != nil {
			if pk, err := hpke.NewDHKEMPublicKey(e); err == nil {
				return bundleSuites[1], pk, nil
			}
		}
	}
	return bundleSuite{}, nil, errors.New("CEKpub is neither an MLKEM768-P256 encapsulation key nor a P-256 SubjectPublicKeyInfo")
}

func bundleLP(b []byte, parts ...[]byte) []byte {
	for _, p := range parts {
		b = binary.BigEndian.AppendUint32(b, uint32(len(p)))
		b = append(b, p...)
	}
	return b
}

// BundleInfo is the HPKE info of the container.
func BundleInfo(target string, freshness []byte) []byte {
	return bundleLP(nil, []byte(bundleInfoLabel), []byte(target), freshness)
}

// CanonicalJSON is the JSON Canonicalization Scheme (RFC 8785) of v, for the values a bundle carries: object keys
// sorted, no insignificant space, strings escaped as Section 3.2.2.2 says, integers as they are.
func CanonicalJSON(v any) ([]byte, error) {
	raw, err := json.Marshal(v)
	if err != nil {
		return nil, err
	}
	var tree any
	d := json.NewDecoder(bytes.NewReader(raw))
	d.UseNumber()
	if err := d.Decode(&tree); err != nil {
		return nil, err
	}
	var buf bytes.Buffer
	if err := writeCanonical(&buf, tree); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func writeCanonical(buf *bytes.Buffer, v any) error {
	switch t := v.(type) {
	case map[string]any:
		keys := make([]string, 0, len(t))
		for k := range t {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		buf.WriteByte('{')
		for i, k := range keys {
			if i > 0 {
				buf.WriteByte(',')
			}
			writeCanonicalString(buf, k)
			buf.WriteByte(':')
			if err := writeCanonical(buf, t[k]); err != nil {
				return err
			}
		}
		buf.WriteByte('}')
	case []any:
		buf.WriteByte('[')
		for i, e := range t {
			if i > 0 {
				buf.WriteByte(',')
			}
			if err := writeCanonical(buf, e); err != nil {
				return err
			}
		}
		buf.WriteByte(']')
	case string:
		writeCanonicalString(buf, t)
	case json.Number:
		buf.WriteString(t.String())
	case bool:
		if t {
			buf.WriteString("true")
		} else {
			buf.WriteString("false")
		}
	case nil:
		buf.WriteString("null")
	default:
		return fmt.Errorf("cannot encode %T", v)
	}
	return nil
}

// writeCanonicalString writes s as RFC 8785 Section 3.2.2.2 says: only the quotation mark, the reverse solidus and
// the control characters are escaped, the latter as \b \t \n \f \r or \u00xx in lowercase hex.
func writeCanonicalString(buf *bytes.Buffer, s string) {
	buf.WriteByte('"')
	for _, r := range s {
		switch {
		case r == '"':
			buf.WriteString(`\"`)
		case r == '\\':
			buf.WriteString(`\\`)
		case r == '\n':
			buf.WriteString(`\n`)
		case r == '\r':
			buf.WriteString(`\r`)
		case r == '\t':
			buf.WriteString(`\t`)
		case r == '\b':
			buf.WriteString(`\b`)
		case r == '\f':
			buf.WriteString(`\f`)
		case r < 0x20:
			fmt.Fprintf(buf, `\u%04x`, r)
		default:
			buf.WriteRune(r)
		}
	}
	buf.WriteByte('"')
}

// SealCredentialBundle seals bundle to CEKpub under the suite CEKpub's encoding names, with the group, the Target,
// the freshness element and the Credential Hint in the associated data. Anyone who saw CEKpub can seal a container to
// it: the container carries no origin authentication, which is the profile's accepted risk.
func SealCredentialBundle(
	bundle *CredentialBundle,
	groupID string,
	cekPub []byte,
	handle []byte,
	target, credentialHint string,
) (*EncryptedCredentialBundle, error) {
	s, pk, err := bundleSuiteOf(cekPub)
	if err != nil {
		return nil, fmt.Errorf("invalid CEK public key: %w", err)
	}
	kdf, aead := bundleKDFAEAD()
	aad := BundleAAD{GroupID: groupID, Target: B64URL(target), Handle: handle, CredentialHint: credentialHint}
	info := BundleInfo(target, handle)
	enc, snd, err := hpke.NewSender(pk, kdf, aead, info)
	if err != nil {
		return nil, fmt.Errorf("failed to set up HPKE: %w", err)
	}
	aadBytes, err := CanonicalJSON(aad)
	if err != nil {
		return nil, err
	}
	pt, err := CanonicalJSON(bundle)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal credential bundle: %w", err)
	}
	ct, err := snd.Seal(aadBytes, pt)
	if err != nil {
		return nil, fmt.Errorf("failed to seal credential bundle: %w", err)
	}
	return &EncryptedCredentialBundle{Container: BundleContainer, Suite: s.suite, Enc: enc, Ciphertext: ct, AAD: aad}, nil
}

// CEKPrivateKey is a CEK as the HPKE recipient takes it: the MLKEM768-P256 key itself, or a P-256 key as ECDSA or
// ECDH.
func CEKPrivateKey(k crypto.PrivateKey) (hpke.PrivateKey, error) {
	switch p := k.(type) {
	case hpke.PrivateKey:
		return p, nil
	case *ecdh.PrivateKey:
		return hpke.NewDHKEMPrivateKey(p)
	case *ecdsa.PrivateKey:
		e, err := p.ECDH()
		if err != nil {
			return nil, err
		}
		return hpke.NewDHKEMPrivateKey(e)
	}
	return nil, fmt.Errorf("a CEK of type %T opens no container", k)
}

// Refusals of Open.
var (
	ErrBundleContainer = errors.New("not the hpke-base container, or not one of its suites")
	ErrBundleAAD       = errors.New("the associated data does not name what the Evidence bound")
)

// Open checks the container, its suite and the associated data against what the Attester bound, then decrypts under
// the CEK. Who sealed the container it cannot tell: a container anyone sealed to CEKpub opens, which is the profile's
// accepted risk (Security Considerations of the draft). cekPub is CEKpub as the request carried it.
func (b *EncryptedCredentialBundle) Open(
	cekPriv crypto.PrivateKey,
	cekPub []byte,
	target string,
	handle []byte,
	credentialHint string,
) (*CredentialBundle, error) {
	if b.Container != BundleContainer {
		return nil, ErrBundleContainer
	}
	if !bytes.Equal(b.AAD.Target, []byte(target)) || !bytes.Equal(b.AAD.Handle, handle) || b.AAD.CredentialHint != credentialHint {
		return nil, ErrBundleAAD
	}
	info := BundleInfo(target, handle)
	aadBytes, err := CanonicalJSON(b.AAD)
	if err != nil {
		return nil, err
	}
	// the suite: one the profile sets, and the one CEKpub's encoding names
	if s, _, err := bundleSuiteOf(cekPub); err != nil || b.Suite != s.suite {
		return nil, ErrBundleContainer
	}
	cek, err := CEKPrivateKey(cekPriv)
	if err != nil {
		return nil, err
	}
	kdf, aead := bundleKDFAEAD()
	r, err := hpke.NewRecipient(b.Enc, cek, kdf, aead, info)
	if err != nil {
		return nil, fmt.Errorf("failed to set up HPKE: %w", err)
	}
	pt, err := r.Open(aadBytes, b.Ciphertext)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt credential bundle: %w", err)
	}
	var bundle CredentialBundle
	if err := json.Unmarshal(pt, &bundle); err != nil {
		return nil, fmt.Errorf("failed to unmarshal credential bundle: %w", err)
	}
	return &bundle, nil
}
