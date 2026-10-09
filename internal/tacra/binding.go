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
// It is the nonce of the Verifier's session, which the Verifier finds in the Evidence and the RRP recomputes.
// est.BindingDigest of this repository puts the server identity before the Target, the order before 30 September
// 2026; it is not used here.
func bindingValue(handle []byte, target, rrpID string, subject []byte) []byte {
	var in []byte
	for _, v := range [][]byte{handle, []byte(target), []byte(rrpID), subject} {
		in = binary.BigEndian.AppendUint32(in, uint32(len(v)))
		in = append(in, v...)
	}
	sum := sha512.Sum512(in)
	return sum[:]
}
