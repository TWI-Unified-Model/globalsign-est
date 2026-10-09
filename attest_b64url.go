package est

import (
	"encoding/base64"
	"encoding/json"
	"strings"
)

// B64URL is a byte string of the attested-acquisition envelopes. JSON carries it as unpadded base64url, as
// draft-novak-lamps-tacra-est's Envelope Definitions require ("in the JSON encoding, bstr members carry the
// unpadded base64url encoding of the octets"); a plain []byte would carry padded standard base64. Unmarshal
// also takes padded standard base64, which this package wrote before, so that an older peer still works.
type B64URL []byte

// MarshalJSON encodes b as unpadded base64url.
func (b B64URL) MarshalJSON() ([]byte, error) {
	return json.Marshal(base64.RawURLEncoding.EncodeToString(b))
}

// UnmarshalJSON decodes unpadded base64url, or padded standard base64.
func (b *B64URL) UnmarshalJSON(data []byte) error {
	var s string
	if err := json.Unmarshal(data, &s); err != nil {
		return err
	}
	if v, err := base64.RawURLEncoding.DecodeString(strings.TrimRight(s, "=")); err == nil {
		*b = v
		return nil
	}
	v, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		return err
	}
	*b = v
	return nil
}
