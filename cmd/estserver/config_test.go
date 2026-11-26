package main

import (
	"encoding/json"
	"os"
	"strings"
	"testing"
)

// The configuration's rules, on the sample (the mock CA), the example (the TACRA backend), and each with one field
// changed. The server itself starts with a deployment's configuration in every run of the bench.

func TestSampleAndExample(t *testing.T) {
	cfg, err := parseConfig([]byte(sample))
	if err != nil {
		t.Fatalf("sample: %v", err)
	}
	if cfg.MockCA == nil || cfg.Attest == nil || cfg.Tacra != nil {
		t.Fatal("the sample is the mock CA's configuration: mock_ca and attest, no tacra section")
	}
	example, err := os.ReadFile("../../estserver.json.example")
	if err != nil {
		t.Fatal(err)
	}
	if cfg, err = parseConfig(example); err != nil {
		t.Fatalf("example: %v", err)
	}
	if cfg.Tacra == nil || len(cfg.Tacra.Verifiers) == 0 || len(cfg.Tacra.RelyingParties) == 0 || len(cfg.Tacra.Targets) == 0 {
		t.Fatal("the example is the TACRA backend's configuration: a tacra section with verifiers, RATS Relying Parties and Targets")
	}
}

// changed is base with one change made.
func changed(t *testing.T, base []byte, change func(map[string]any)) []byte {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal(base, &m); err != nil {
		t.Fatal(err)
	}
	change(m)
	b, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestRefused(t *testing.T) {
	example, err := os.ReadFile("../../estserver.json.example")
	if err != nil {
		t.Fatal(err)
	}
	section := func(m map[string]any, k string) map[string]any { return m[k].(map[string]any) }
	for _, c := range []struct {
		name string
		data []byte
		want string
	}{
		{"the mock CA beside the tacra section", changed(t, example, func(m map[string]any) {
			m["mock_ca"] = map[string]any{"certificates": "/path/to/CA/certificates.pem", "private_key": "/path/to/CA/private/key.pem"}
		}), "do not mix"},
		{"the mock attested CA beside the tacra section", changed(t, example, func(m map[string]any) {
			m["attest"] = map[string]any{"trusted_provider_public_key": "/path/to/provider/public/key.pem"}
		}), "do not mix"},
		{"the tacra section without tls", changed(t, example, func(m map[string]any) { delete(m, "tls") }), "no tls section"},
		{"the tacra section without a server key", changed(t, example, func(m map[string]any) { delete(section(m, "tls"), "private_key") }),
			"tls: listen_address, certificates and private_key are required"},
		{"a RATS Relying Party's field misspelt", changed(t, example, func(m map[string]any) {
			relyingParty := section(section(section(m, "tacra"), "rrps"), "ca")
			relyingParty["rrpid"] = relyingParty["rrp_id"]
			delete(relyingParty, "rrp_id")
		}), `unknown field "rrpid"`},
		{"a field the server does not know", changed(t, []byte(sample), func(m map[string]any) { m["mock-ca"] = m["mock_ca"] }),
			`unknown field "mock-ca"`},
		{"a second object after the first", []byte(sample + sample), "data after the configuration object"},
	} {
		if _, err := parseConfig(c.data); err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: got %v, want an error with %q", c.name, err, c.want)
		}
	}
}

func TestTheMockCAAlone(t *testing.T) {
	for name, data := range map[string][]byte{
		"the sample":                 []byte(sample),
		"without tls, transient":     changed(t, []byte(sample), func(m map[string]any) { delete(m, "tls") }),
		"without mock_ca, transient": changed(t, []byte(sample), func(m map[string]any) { delete(m, "mock_ca") }),
	} {
		if _, err := parseConfig(data); err != nil {
			t.Errorf("%s: %v", name, err)
		}
	}
}

// credentialAcquisition is a configuration of the server that hosts the CAS Server Plug-in of TACRA.
const credentialAcquisition = `{
    "tls": {"listen_address": ":8443", "certificates": "/etc/est/tls-cert.pem", "private_key": "/etc/est/tls-key.pem"},
    "credential_acquisition": {
        "ca_certs": "/etc/est/workload-ca.pem",
        "acceptable_evidence": ["application/psa-attestation-token"],
        "verifier": {"veraison": {"url": "https://verifier.example", "ear_key_path": "/etc/est/veraison-ear.jwk",
                                  "evidence_media_types": ["application/psa-attestation-token"], "submods": ["PSA_IOT"]}},
        "target": {"https://server.example": {"mode": "enroll", "verifiers": ["veraison"], "measurements": ["a0a1a2"],
                                              "certificate_name": "client.example",
                                              "retrieve_credential_types": ["jwt"], "secret_path": "tacra/server-token"}},
        "secret_vault": {"kind": "hashicorp", "url": "http://vault.example:8200", "token_path": "/etc/est/vault-token"},
        "credential_authority": {"kind": "step-ca", "url": "https://ca.example:9000", "ca_path": "/etc/est/step-ca-root.pem",
                                 "provisioner": "tacra", "provisioner_key_path": "/etc/est/provisioner-key.json"}
    },
    "healthcheck_password": "xyzzy", "rate_limit": 150, "timeout": 30
}`

func TestCredentialAcquisition(t *testing.T) {
	cfg, err := parseConfig([]byte(credentialAcquisition))
	if err != nil {
		t.Fatalf("the configuration of the CAS Server Plug-in: %v", err)
	}
	section := cfg.CredentialAcquisition
	if section == nil || section.CACerts != "/etc/est/workload-ca.pem" || section.CredentialAuthority == nil ||
		section.SecretVault == nil || section.Target["https://server.example"].SecretPath != "tacra/server-token" {
		t.Fatalf("the section was not read: %+v", section)
	}

	part := func(m map[string]any, k string) map[string]any { return m[k].(map[string]any) }
	for _, c := range []struct {
		name string
		data []byte
		want string
	}{
		{"beside the mock CA", changed(t, []byte(credentialAcquisition), func(m map[string]any) {
			m["mock_ca"] = map[string]any{"certificates": "/path/to/CA/certificates.pem", "private_key": "/path/to/CA/private/key.pem"}
		}), "credential_acquisition does not mix"},
		{"beside the mock attested CA", changed(t, []byte(credentialAcquisition), func(m map[string]any) {
			m["attest"] = map[string]any{"trusted_provider_public_key": "/path/to/provider/public/key.pem"}
		}), "credential_acquisition does not mix"},
		{"without tls", changed(t, []byte(credentialAcquisition), func(m map[string]any) { delete(m, "tls") }),
			"no tls section: with credential_acquisition"},
		{"without a server key", changed(t, []byte(credentialAcquisition), func(m map[string]any) { delete(part(m, "tls"), "private_key") }),
			"tls: listen_address, certificates and private_key are required"},
		{"a field of the section misspelt", changed(t, []byte(credentialAcquisition), func(m map[string]any) {
			acquisition := part(m, "credential_acquisition")
			acquisition["targets"] = acquisition["target"]
			delete(acquisition, "target")
		}), `unknown field "targets"`},
	} {
		if _, err := parseConfig(c.data); err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: got %v, want an error with %q", c.name, err, c.want)
		}
	}
}
