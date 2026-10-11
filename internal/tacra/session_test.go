package tacra

import (
	"encoding/hex"
	"net/http"
	"testing"
	"time"

	"github.com/globalsign/est"
)

// The sessions the EST server keeps between attest-initiate and the second leg. The case that showed the fault, an
// attack run of 7 October 2026: attest-initiate for https://db-epoch.tacra.example (x509) and then for
// https://ledger-epoch.tacra.example (api-key) returned the same Handle, the deployment's epoch, and the Enrollment
// at db-epoch that followed was refused (403) because the second session had replaced the first.

func status(err error) int {
	if err == nil {
		return http.StatusOK
	}
	if e, ok := err.(*httpError); ok {
		return e.StatusCode()
	}
	return 0
}

func TestEpochSharedByTargets(t *testing.T) {
	b := &Backend{sessions: map[string][]session{}}
	key, live := hex.EncodeToString([]byte("an epoch marker of 32 octets....")), time.Now().Add(5*time.Minute)
	b.remember(key, session{"https://db-epoch.tacra.example", "x509", "ca", est.FreshnessPresentEpoch, live})
	b.remember(key, session{"https://ledger-epoch.tacra.example", "api-key", "vault", est.FreshnessPresentEpoch, live})
	for range 2 { // an epoch serves every second leg while it lives
		for _, c := range []struct{ target, ctype string }{
			{"https://db-epoch.tacra.example", "x509"},
			{"https://ledger-epoch.tacra.example", "api-key"},
		} {
			if got := status(b.correlateKey(est.FreshnessPresentEpoch, key, c.target, c.ctype)); got != http.StatusOK {
				t.Fatalf("%s: %d, want 200", c.target, got)
			}
		}
	}
	if got := status(b.correlateKey(est.FreshnessPresentEpoch, key, "https://db-nonce.tacra.example", "x509")); got != http.StatusForbidden {
		t.Fatalf("a Target that asked for no Initiate: %d, want 403", got)
	}
	// asking again for the same Target replaces its session rather than adding one
	b.remember(key, session{"https://db-epoch.tacra.example", "x509", "ca", est.FreshnessPresentEpoch, live})
	if n := len(b.sessions[key]); n != 2 {
		t.Fatalf("%d sessions for the epoch, want 2", n)
	}
}

func TestNonceSingleUse(t *testing.T) {
	b := &Backend{sessions: map[string][]session{}}
	key := "a present-nonce Handle"
	b.remember(key, session{"https://db-nonce.tacra.example", "x509", "ca", est.FreshnessPresentNonce, time.Now().Add(time.Minute)})
	if got := status(b.correlateKey(est.FreshnessPresentNonce, key, "https://db-nonce.tacra.example", "api-key")); got != http.StatusForbidden {
		t.Fatalf("another Credential Type: %d, want 403", got)
	}
	if got := status(b.correlateKey(est.FreshnessPresentNonce, key, "https://db-nonce.tacra.example", "x509")); got != http.StatusOK {
		t.Fatalf("its own second leg: %d, want 200", got)
	}
	if got := status(b.correlateKey(est.FreshnessPresentNonce, key, "https://db-nonce.tacra.example", "x509")); got != http.StatusConflict {
		t.Fatalf("the Handle again: %d, want 409", got)
	}
}

func TestExpiredOrUnknown(t *testing.T) {
	b := &Backend{sessions: map[string][]session{}}
	b.remember("old", session{"https://db-nonce.tacra.example", "x509", "ca", est.FreshnessPresentNonce, time.Now().Add(-time.Second)})
	for _, key := range []string{"old", "never returned"} {
		if got := status(b.correlateKey(est.FreshnessPresentNonce, key, "https://db-nonce.tacra.example", "x509")); got != http.StatusConflict {
			t.Fatalf("%s: %d, want 409", key, got)
		}
	}
	if got := status(b.correlateKey(est.FreshnessAbsentNone, "", "https://db-none.tacra.example", "x509")); got != http.StatusOK {
		t.Fatalf("a kind without a Handle: %d, want 200 (the RRP checks it)", got)
	}
}

// A second leg refused for its Evidence format (415) leaves its Handle to the next request: the server checks the format
// before it correlates the Handle, as the draft's processing validates the media type first.
func TestFormatRefusalLeavesTheHandle(t *testing.T) {
	const target = "https://db-nonce.tacra.example"
	b := &Backend{sessions: map[string][]session{},
		cfg: Config{RRPs: map[string]RRP{"ca": {Mode: est.MechanismEnroll}},
			Targets: map[string]string{target: "ca"}, AcceptableEvidence: []string{"application/vnd.veraison.tsm-report+cbor"}}}
	handle := []byte("a present-nonce Handle of 32 o.")
	b.remember(hex.EncodeToString(handle), session{target, "x509", "ca", est.FreshnessPresentNonce, time.Now().Add(time.Minute)})
	_, err := b.EnrollCredential(t.Context(), &est.AttestedEnrollmentRequest{Target: target, CredentialType: "x509",
		FreshnessKind: est.FreshnessPresentNonce, Handle: handle, Profile: "application/vnd.example.unknown"}, "", nil)
	if got := status(err); got != http.StatusUnsupportedMediaType {
		t.Fatalf("an Evidence format not accepted: %d (%v), want 415", got, err)
	}
	if got := status(b.correlate(est.FreshnessPresentNonce, handle, target, "x509")); got != http.StatusOK {
		t.Fatalf("the Handle after the 415: %d, want 200: the refusal used it up", got)
	}
}
