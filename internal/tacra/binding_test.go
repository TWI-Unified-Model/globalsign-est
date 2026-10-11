package tacra

import (
	"bytes"
	"crypto/sha512"
	"encoding/binary"
	"testing"

	"github.com/globalsign/est"
)

// The binding of 11 October 2026: three length-prefixed fields, the freshness element, the Target and the subject; the
// same octets the mock's est.BindingDigest computes. (A hardware vector follows the first run of this layout.)
func TestBindingValueThreeFields(t *testing.T) {
	handle, subject := []byte("a Handle"), []byte("a CSR")
	const target = "https://db.tacra.example"
	var in []byte
	for _, v := range [][]byte{handle, []byte(target), subject} {
		in = binary.BigEndian.AppendUint32(in, uint32(len(v)))
		in = append(in, v...)
	}
	want := sha512.Sum512(in)
	if got := bindingValue(handle, target, subject); !bytes.Equal(got, want[:]) {
		t.Fatalf("binding value %x, want %x", got, want)
	}
	if got := est.BindingDigest(handle, target, subject); !bytes.Equal(got, want[:]) {
		t.Fatalf("est.BindingDigest %x differs from the backend's %x: one layout is meant", got, want)
	}
	if bytes.Equal(bindingValue(handle, target, subject), bindingValue(handle, "https://other.tacra.example", subject)) {
		t.Fatal("the Target is not bound")
	}
}
