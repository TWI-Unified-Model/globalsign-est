package est

import (
	"encoding/base64"
	"encoding/json"
	"errors"
)

// B64URL is a byte string of the attested-acquisition envelopes. JSON carries it as a text string holding its unpadded
// base64url encoding (RFC 4648, Section 5), as the wire format proposed for draft-novak-lamps-tacra-est says in CDDL
// with the control .b64u of RFC 9741; a plain []byte would carry padded standard base64.
type B64URL []byte

// MarshalJSON encodes b as unpadded base64url.
func (b B64URL) MarshalJSON() ([]byte, error) {
	return json.Marshal(base64.RawURLEncoding.EncodeToString(b))
}

// UnmarshalJSON decodes unpadded base64url as .b64u takes it, and nothing else (decodeB64U).
func (b *B64URL) UnmarshalJSON(data []byte) error {
	var s string
	if err := json.Unmarshal(data, &s); err != nil {
		return err
	}
	v, err := decodeB64U(s)
	if err != nil {
		return err
	}
	*b = v
	return nil
}

var errNotB64U = errors.New("not unpadded base64url")

// decodeB64U decodes s as CDDL's .b64u takes it (RFC 9741, Section 2.1): the base64url alphabet only (RFC 4648,
// Section 5), no padding, and the bits of the last character that encode no octet zero. Go's decoder alone would
// also take line breaks inside s.
func decodeB64U(s string) ([]byte, error) {
	for i := 0; i < len(s); i++ {
		switch c := s[i]; {
		case 'A' <= c && c <= 'Z', 'a' <= c && c <= 'z', '0' <= c && c <= '9', c == '-', c == '_':
		default:
			return nil, errNotB64U
		}
	}
	v, err := base64.RawURLEncoding.Strict().DecodeString(s)
	if err != nil {
		return nil, errNotB64U
	}
	return v, nil
}
