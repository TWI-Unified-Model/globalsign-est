package tacra

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/globalsign/est"
)

// signedJWS is a compact JWS over header and payload, signed ES256 by key, the way the verifier signs its Attestation
// Results and the RRP gateway checks them.
func signedJWS(t *testing.T, key *ecdsa.PrivateKey, header, payload string) string {
	t.Helper()
	h := base64.RawURLEncoding.EncodeToString([]byte(header))
	p := base64.RawURLEncoding.EncodeToString([]byte(payload))
	digest := sha256.Sum256([]byte(h + "." + p))
	r, s, err := ecdsa.Sign(rand.Reader, key, digest[:])
	if err != nil {
		t.Fatal(err)
	}
	sig := make([]byte, 64)
	r.FillBytes(sig[:32])
	s.FillBytes(sig[32:])
	return h + "." + p + "." + base64.RawURLEncoding.EncodeToString(sig)
}

func verifies(t *testing.T, pub *ecdsa.PublicKey, jws string) bool {
	t.Helper()
	parts := strings.Split(jws, ".")
	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil || len(sig) != 64 {
		t.Fatalf("signature: %v, %d octets", err, len(sig))
	}
	digest := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	return ecdsa.Verify(pub, digest[:], new(big.Int).SetBytes(sig[:32]), new(big.Int).SetBytes(sig[32:]))
}

func TestConduitResignsWithItsOwnKey(t *testing.T) {
	verifier, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	jws := signedJWS(t, verifier, `{"alg":"ES256","kid":"veraison"}`, `{"eat_nonce":"AQID","submods":{}}`)
	logPath := filepath.Join(t.TempDir(), "est-conduit.log")
	c, err := newConduit(logPath)
	if err != nil {
		t.Fatal(err)
	}
	out, err := c.resign(jws)
	if err != nil {
		t.Fatal(err)
	}
	in, re := strings.Split(jws, "."), strings.Split(out, ".")
	if in[0] != re[0] || in[1] != re[1] {
		t.Fatal("the header or the payload changed: only the signature may")
	}
	if in[2] == re[2] {
		t.Fatal("the signature did not change")
	}
	if verifies(t, &verifier.PublicKey, out) {
		t.Fatal("the verifier's key still verifies what the conduit signed")
	}
	if !verifies(t, &c.key.PublicKey, out) {
		t.Fatal("the conduit's own key does not verify its signature")
	}
	if !verifies(t, &verifier.PublicKey, jws) {
		t.Fatal("the original no longer verifies under the verifier's key: the test's own signing is wrong")
	}
	c.logf("enroll", "https://db.tacra.example", "Attestation Results of verifier %s signed again", "veraison")
	logged, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"conduit attack verifier, this server's own verifier key: SPKI SHA-256 " + c.spki,
		"conduit attack verifier: Enrollment for https://db.tacra.example: Attestation Results of verifier veraison signed again",
	} {
		if !strings.Contains(string(logged), want) {
			t.Fatalf("the conduit log lacks %q:\n%s", want, logged)
		}
	}
}

func TestConduitRefusesWhatIsNotAJWS(t *testing.T) {
	c, err := newConduit("")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.resign("not.a-jws"); err == nil {
		t.Fatal("two parts taken for a compact JWS")
	}
}

func TestNewTakesTheDrillInPassportAlone(t *testing.T) {
	ca := caFile(t)
	cfg := func(attack, model string) Config {
		return Config{
			Verifiers: map[string]Verifier{"veraison": {URL: "https://" + closedPort(t), CA: ca, Provider: "sev_guest"}},
			RRPs: map[string]RRP{"ca": {URL: "https://" + closedPort(t), CA: ca, RRPID: "https://ca1.tacra.example",
				Mode: est.MechanismEnroll, Verifiers: []string{"veraison"}, RATSModel: model, ConduitAttack: attack}},
			Targets:            map[string]string{"https://db-none.tacra.example": "ca"},
			AcceptableEvidence: []string{"application/vnd.veraison.tsm-report+cbor"},
			ConduitLog:         filepath.Join(t.TempDir(), "est-conduit.log"),
		}
	}
	if _, err := New(cfg("forge", "")); err == nil || !strings.Contains(err.Error(), "conduit_attack") {
		t.Fatalf("an unknown drill accepted: %v", err)
	}
	if _, err := New(cfg(conduitVerifier, backgroundCheck)); err == nil || !strings.Contains(err.Error(), "Passport drill") {
		t.Fatalf("the verifier drill accepted in Background Check: %v", err)
	}
	b, err := New(cfg(conduitVerifier, passport))
	if err != nil {
		t.Fatal(err)
	}
	if b.conduit == nil || b.conduit.key == nil {
		t.Fatal("the verifier drill configured, but no conduit key made")
	}
	if b, err = New(cfg("", "")); err != nil || b.conduit != nil {
		t.Fatalf("an honest server made a conduit: %v %v", b.conduit, err)
	}
}
