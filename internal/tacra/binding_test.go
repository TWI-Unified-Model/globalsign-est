package tacra

import (
	"bytes"
	"encoding/hex"
	"testing"

	"github.com/globalsign/est"
)

// A hardware test vector of the binding without the RRP identifier: the present-nonce Enrollment case of the bench's
// GCP SEV-SNP run 20261008T205230Z-gcp-sev-snp-no-rrp-id (nikolaichuk7/attestation-bench, hwcheck/evidence), whose
// SHA-512(binding_input) with an empty identifier field equals REPORT_DATA of the hardware report (offset 0x50), and
// whose value with the Credential Authority's identifier does not.
func TestBindingValueHardwareVector(t *testing.T) {
	handle, _ := hex.DecodeString("2550eda6542e3466031c0f27e11172dba8b8a793327cb3ba0c1e45529b0b1766")
	subject, _ := hex.DecodeString("3081dc3081830201003021311f301d06035504031316776f726b6c6f61642e74616372612e6578616d706c653059301306072a8648ce3d020106082a8648ce3d03010703420004d0ac20c555d1ed5bbd290a175a8781abfe2349f9145894e10061f4857f79d4ad9aa22d02619323708103d3cd3335a5b79127d325154601d35195566042cd99d9a000300a06082a8648ce3d0403020348003045022100a11c21faec75689d10bd28d37e785e21f76e43a84c58c17e8176947c0e678b9a0220013be8138ce258355ab354df531ff840d3c34bf8322d68d27e50385a679022d0")
	reportData, _ := hex.DecodeString("2c9ff509e7312ca53bc61ce96a03e73323d9b12e076ee0333aadc5123eaff848523a6615ff9ea27cd9681b0dd60c60a2631776c7d230c88f63a70e3fd37c4e04")
	const target = "https://db.tacra.example"
	if len(subject) != 223 || len(reportData) != 64 {
		t.Fatalf("vector: subject %d octets, REPORT_DATA %d", len(subject), len(reportData))
	}
	if got := bindingValue(handle, target, subject); !bytes.Equal(got, reportData) {
		t.Fatalf("binding value %x, want REPORT_DATA %x", got, reportData)
	}
	// the repository's own encoder has another layout (no identifier field at all), and so another value
	if bytes.Equal(est.BindingDigest(handle, target, subject), reportData) {
		t.Fatal("est.BindingDigest now gives the TACRA layout: this backend can use it again")
	}
}

// The layout of Section 4.5 is kept: the identifier field is present and empty, so that the value equals the one an
// RRP computes with an empty identifier, as the bench's RRPs did in the runs of 8 October 2026.
func TestBindingValueEmptyIdentifierField(t *testing.T) {
	handle, subject := []byte("h"), []byte("a CSR")
	const target = "https://db.tacra.example"
	var in []byte
	for _, v := range [][]byte{handle, []byte(target), nil, subject} {
		in = append(in, byte(len(v)>>24), byte(len(v)>>16), byte(len(v)>>8), byte(len(v)))
		in = append(in, v...)
	}
	if got := bindingValue(handle, target, subject); !bytes.Equal(got, sha512Sum(in)) {
		t.Errorf("binding value %x, want the layout with an empty third field", got)
	}
}
