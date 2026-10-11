package tacra

import (
	"bytes"
	"crypto/sha512"
	"encoding/binary"
	"encoding/hex"
	"testing"

	"github.com/globalsign/est"
)

// A hardware vector of the three-field binding: the present-nonce Enrollment of the bench's GCP SEV-SNP run
// 20261011T151929Z-gcp-sev-snp (nikolaichuk7/attestation-bench, hwcheck/evidence), made with this tree (b531556) on
// 11 October 2026, whose REPORT_DATA (offset 0x50 of the report) equals SHA-512(binding_input).
func TestBindingValueHardwareVector(t *testing.T) {
	handle, _ := hex.DecodeString("a8dd37281155a104a3565cc7ce2057d508dd978c00b2f1fa1e2591da88d508b3")
	subject, _ := hex.DecodeString("3081dc3081830201003021311f301d06035504031316776f726b6c6f61642e74616372612e6578616d706c653059301306072a8648ce3d020106082a8648ce3d030107034200043f7db1f117615222a44ba5aa38e46f081aba244ac212b9a4fdad6b32c1d652efc8ee87a58a5c527c8fb3f99fb73e9672ee16295162a644d1d8f347514a3cc334a000300a06082a8648ce3d0403020348003045022100faac6730de9d236b9ceda664aaa5c8141ca611994b2be69e7d9faf1a1643aed2022023ddf3e5bd48fcb1e9ced32a21b73a81385f4763a752dfc3d735b7d313998968")
	reportData, _ := hex.DecodeString("79e35ac63f0dd8ec89d31afcab8ede5d993de21003af1b16d90f43c5a8f788f99cd8013e75f615ede1acb4fcee27d732063570e97b8a22c2da8d5eec8240c4fd")
	const target = "https://db.tacra.example"
	if len(subject) != 223 || len(reportData) != 64 {
		t.Fatalf("vector: subject %d octets, REPORT_DATA %d", len(subject), len(reportData))
	}
	if got := bindingValue(handle, target, subject); !bytes.Equal(got, reportData) {
		t.Fatalf("binding value %x, want REPORT_DATA %x", got, reportData)
	}
	if got := est.BindingDigest(handle, target, subject); !bytes.Equal(got, reportData) {
		t.Fatalf("est.BindingDigest %x differs from REPORT_DATA: the mock and the backend are meant to bind one way", got)
	}
}

// The binding of 11 October 2026: three length-prefixed fields, the freshness element, the Target and the subject; the
// same octets the mock's est.BindingDigest computes.
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
