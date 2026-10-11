package tacra

import (
	"crypto/sha512"
	"encoding/binary"
)

// bindingValue is SHA-512 of the binding input of TACRA Section 4.5 (master 912bd50 and later) and of
// draft-novak-lamps-tacra-est, Section 9.1.5 (pull request head 183bedd): the freshness element, the Target, the
// identifier of the RATS Relying Party and the subject, each preceded by its length as a 32-bit big-endian integer.
//
//	binding_input = len32(handle) || handle || len32(target) || target
//	             || len32(rrp_id) || rrp_id || len32(subject) || subject
//
// Since the group's decision of 6 October 2026 (TheBankster/rats-tacra#20) the RRP identifier is left out: the field
// is empty, len32(0) and nothing, until the threat model is agreed and the identifier may return. The Evidence of the
// bench's runs without the identifier (8 October 2026) carries exactly this value in REPORT_DATA (binding_test.go).
// It is the nonce of the Verifier's session, which the Verifier finds in the Evidence and the RRP recomputes.
// est.BindingDigest of this repository puts the server identity before the Target, the order before 30 September
// 2026; it is not used here.
func bindingValue(handle []byte, target string, subject []byte) []byte {
	var in []byte
	// the third field, the RRP identifier, is empty: the group's decision of 6 October 2026 (TheBankster/rats-tacra#20)
	// leaves it out until the threat model is agreed; the layout of Section 4.5 is kept so that it can return
	for _, v := range [][]byte{handle, []byte(target), nil, subject} {
		in = binary.BigEndian.AppendUint32(in, uint32(len(v)))
		in = append(in, v...)
	}
	sum := sha512.Sum512(in)
	return sum[:]
}

// sha512Sum is SHA-512 of in; the tests use it to spell the layout out.
func sha512Sum(in []byte) []byte {
	sum := sha512.Sum512(in)
	return sum[:]
}
