package tacra

import (
	"crypto/sha512"
	"encoding/binary"
)

// bindingValue is SHA-512 of the binding input of TACRA Section 4.5 as the group decided on 6 and 11 October 2026
// (TheBankster/rats-tacra#20; TWI-Unified-Model/globalsign-est#4): the freshness element, the Target and the subject,
// each preceded by its length as a 32-bit big-endian integer; no Relying Party identifier and no server identifier.
//
//	binding_input = len32(handle) || handle || len32(target) || target || len32(subject) || subject
//
// It is the nonce of the Verifier's session, which the Verifier finds in the Evidence and the RRP recomputes. The
// mock's est.BindingDigest computes the same octets (binding_test.go).
func bindingValue(handle []byte, target string, subject []byte) []byte {
	var in []byte
	for _, v := range [][]byte{handle, []byte(target), subject} {
		in = binary.BigEndian.AppendUint32(in, uint32(len(v)))
		in = append(in, v...)
	}
	sum := sha512.Sum512(in)
	return sum[:]
}
