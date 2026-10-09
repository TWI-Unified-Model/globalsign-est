package tacra

import (
	"encoding/json"
	"maps"
	"slices"
	"testing"
)

// The attest-initiate response the EST server makes of an RRP gateway's answer: the members the CDDL of the proposed
// wire format (attestation-initiation-response) gives the answer's Freshness Kind and mode, never the RRP identifier,
// and a refusal of an answer that breaks the rule of the Handle. The answers are as the RRP gateways of a GCP SEV-SNP
// run gave them, with members added that the kind or the mode does not take.

func TestInitiationResponse(t *testing.T) {
	evidence := []string{"application/vnd.veraison.tsm-report+cbor"}
	const handle = "bBkZVKFxeKhQzmhYZ3ReiqnGG4QAGesKGXP88H4vWVE" // a present-nonce Handle of a GCP SEV-SNP run
	csk, cek := []string{"ecdsa-p256-sha256"}, []string{"MLKEM768-P256+HKDF-SHA256+AES-256-GCM"}
	for _, c := range []struct {
		name    string
		g       gatewayInitiation
		members []string // of the response, or none for a refusal
	}{
		{"present-nonce, enroll", gatewayInitiation{FreshnessKind: "present-nonce", Handle: handle,
			RRPID: "https://ca1.tacra.example", ExpiresIn: 300, MaxAge: 120, Mode: "enroll", AcceptableCSK: csk,
			AcceptableCEK: cek},
			[]string{"acceptable_csk", "acceptable_evidence", "expires_in", "freshness_kind", "handle", "mode"}},
		{"present-epoch, retrieve", gatewayInitiation{FreshnessKind: "present-epoch", Handle: handle,
			RRPID: "https://vault1.tacra.example", ExpiresIn: 300, Mode: "retrieve", AcceptableCSK: csk, AcceptableCEK: cek},
			[]string{"acceptable_cek", "acceptable_evidence", "expires_in", "freshness_kind", "handle", "mode"}},
		{"absent-timestamp, retrieve", gatewayInitiation{FreshnessKind: "absent-timestamp",
			RRPID: "https://vault1.tacra.example", ExpiresIn: 300, MaxAge: 120, Mode: "retrieve", AcceptableCEK: cek},
			[]string{"acceptable_cek", "acceptable_evidence", "freshness_kind", "max_age", "mode"}},
		{"absent-epoch, enroll", gatewayInitiation{FreshnessKind: "absent-epoch", RRPID: "https://ca1.tacra.example",
			ExpiresIn: 300, MaxAge: 120, Mode: "enroll", AcceptableCSK: csk},
			[]string{"acceptable_csk", "acceptable_evidence", "freshness_kind", "mode"}},
		{"absent-none, enroll", gatewayInitiation{FreshnessKind: "absent-none", RRPID: "https://ca1.tacra.example",
			Mode: "enroll", AcceptableCSK: csk}, []string{"acceptable_csk", "acceptable_evidence", "freshness_kind", "mode"}},
		{"present-nonce without a Handle", gatewayInitiation{FreshnessKind: "present-nonce", Mode: "enroll"}, nil},
		{"present-epoch without a Handle", gatewayInitiation{FreshnessKind: "present-epoch", Mode: "retrieve"}, nil},
		{"absent-epoch with a Handle", gatewayInitiation{FreshnessKind: "absent-epoch", Handle: handle, Mode: "enroll"}, nil},
		{"absent-none with a Handle", gatewayInitiation{FreshnessKind: "absent-none", Handle: handle, Mode: "enroll"}, nil},
		{"a Freshness Kind that is not one", gatewayInitiation{FreshnessKind: "present-later", Handle: handle,
			Mode: "enroll"}, nil},
		{"a mode that is not one", gatewayInitiation{FreshnessKind: "absent-none", Mode: "issue"}, nil},
		{"a Handle that is not base64url", gatewayInitiation{FreshnessKind: "present-nonce", Handle: "bBkZ+KFx",
			Mode: "enroll"}, nil},
	} {
		resp, err := initiation(c.g, evidence)
		if c.members == nil {
			if err == nil {
				t.Errorf("%s: answered, want a refusal", c.name)
			}
			continue
		}
		if err != nil {
			t.Errorf("%s: %v", c.name, err)
			continue
		}
		raw, err := json.Marshal(resp)
		if err != nil {
			t.Fatal(err)
		}
		var m map[string]json.RawMessage
		if err := json.Unmarshal(raw, &m); err != nil {
			t.Fatal(err)
		}
		if got := slices.Sorted(maps.Keys(m)); !slices.Equal(got, c.members) {
			t.Errorf("%s: members %v, want %v (%s)", c.name, got, c.members, raw)
		}
		if c.g.Handle != "" && string(m["handle"]) != `"`+c.g.Handle+`"` {
			t.Errorf("%s: handle %s, want the RRP's %q", c.name, m["handle"], c.g.Handle)
		}
	}
}
