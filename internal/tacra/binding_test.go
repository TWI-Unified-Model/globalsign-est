package tacra

import (
	"bytes"
	"encoding/hex"
	"testing"

	"github.com/globalsign/est"
)

// The test vector of draft-novak-lamps-tacra-est, Appendix A (pull request head 183bedd): the enrollment of the
// SEV-SNP run 20260930T172002Z, whose SHA-512(binding_input) equals REPORT_DATA of the hardware report.
func TestBindingValueTestVector(t *testing.T) {
	handle, _ := hex.DecodeString("f8170e6438729e1e3ded60c7c8b220716b7138f9a7e6250c569f1548790ee25f")
	subject, _ := hex.DecodeString("3081dc3081830201003021311f301d06035504030c16776f726b6c6f61642e74616372612e6578616d706c653059301306072a8648ce3d020106082a8648ce3d0301070342000458f74deb3089c1ba23a2a630a94812f503377fa33d252cd5b2a287fefa40bca353ff2671caa8565de5cc5d221d2a61e5610f9748224dd4a210c82bdfa329d7c2a000300a06082a8648ce3d0403020348003045022100a214dc7a98c6dd8c702a38cc2acabbf0fc7391491a546720f69bf29fdbe7056202205708ed7cf3fc25d8f2501639a589a69be2aa8468f97ff4008d3ea124147a0347")
	want, _ := hex.DecodeString("c5d8f3e4a93130e864df61ef1bf940223d8d891fa668d21aceffb34f20473065c3cf80a64ccd0c8c5a60717a5d25cb8b2131bf2e51be88f7beadba6bb181d4ca")
	const target, rrpID = "https://db.tacra.example", "https://ca1.tacra.example"
	if got := bindingValue(handle, target, rrpID, subject); !bytes.Equal(got, want) {
		t.Fatalf("binding value %x, want %x", got, want)
	}
	// the repository's own encoder has the earlier order, and so another value for the same four inputs
	if bytes.Equal(est.BindingDigest(handle, rrpID, target, subject), want) {
		t.Fatal("est.BindingDigest now gives the TACRA order: this backend can use it again")
	}
}
