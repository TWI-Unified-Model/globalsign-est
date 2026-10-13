/*
Copyright (c) 2020 GMO GlobalSign, Inc.

Licensed under the MIT License (the "License"); you may not use this file except
in compliance with the License. You may obtain a copy of the License at

https://opensource.org/licenses/MIT

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"

	"github.com/globalsign/est/internal/mockca"
	"github.com/globalsign/est/internal/tacra"
)

// config contains the EST server configuration. The server runs with the mock
// CA of this fork (mock_ca, attest; transient when absent) or, with a tacra
// section, with the TACRA backend that forwards to deployed verifiers and RRPs
// (internal/tacra; estserver.json.example): one or the other, not both. A
// configuration is decoded strictly: an unknown field is an error.
type config struct {
	MockCA              *mockCAConfig `json:"mock_ca,omitempty"`
	TLS                 *tlsConfig    `json:"tls,omitempty"`
	AllowedHosts        []string      `json:"allowed_hosts,omitempty"`
	Attest              *attestConfig `json:"attest,omitempty"`
	Tacra               *tacra.Config `json:"tacra,omitempty"` // the deployed verifiers and RRPs, instead of the mock
	HealthCheckPassword string        `json:"healthcheck_password"`
	RateLimit           int           `json:"rate_limit"`
	Timeout             int           `json:"timeout"`
	Logfile             string        `json:"log_file"`
	WireLog             string        `json:"wire_log,omitempty"` // every attest-* exchange, as it crossed the wire
}

// attestConfig contains the attested credential acquisition configuration.
// The CAS decides the credential acquisition mechanism per target.
type attestConfig struct {
	Targets                  []mockca.TargetPolicy `json:"targets,omitempty"`
	TrustedProviderPublicKey string                `json:"trusted_provider_public_key"`
}

// mockCAConfig contains the mock CA configuration.
type mockCAConfig struct {
	Certs string `json:"certificates"`
	Key   string `json:"private_key"`
}

// tlsConfig contains the server's TLS configuration.
type tlsConfig struct {
	ListenAddr string   `json:"listen_address"`
	Certs      string   `json:"certificates"`
	Key        string   `json:"private_key"`
	ClientCAs  []string `json:"client_cas,omitempty"`
}

// configFromFile returns a new EST server configuration from a JSON-encoded
// configuration file.
func configFromFile(filename string) (*config, error) {
	data, err := os.ReadFile(filename)
	if err != nil {
		return nil, err
	}
	return parseConfig(data)
}

// parseConfig decodes a configuration strictly: an unknown field, or anything
// after the configuration object, is an error. With a tacra section the
// server's own TLS certificates are required, and the mock CA's sections are
// refused: the server runs one backend or the other.
func parseConfig(data []byte) (*config, error) {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()

	var cfg config
	if err := dec.Decode(&cfg); err != nil {
		return nil, err
	}
	if _, err := dec.Token(); err != io.EOF {
		return nil, errors.New("data after the configuration object")
	}

	if cfg.Tacra != nil {
		switch {
		case cfg.MockCA != nil || cfg.Attest != nil:
			return nil, errors.New("tacra and the mock CA (mock_ca, attest) do not mix: the server runs one or the other")
		case cfg.TLS == nil:
			return nil, errors.New("no tls section: with the TACRA backend the server's certificates and private key are required")
		case cfg.TLS.ListenAddr == "" || cfg.TLS.Certs == "" || cfg.TLS.Key == "":
			return nil, errors.New("tls: listen_address, certificates and private_key are required")
		}
	}

	return &cfg, nil
}

const sample = `{
    "mock_ca": {
        "certificates": "/path/to/CA/certificates.pem",
        "private_key": "/path/to/CA/private/key.pem"
    },
    "tls": {
        "listen_address": "localhost:8443",
        "certificates": "/path/to/server/certificates.pem",
        "private_key": "/path/to/server/private/key.pem",
        "client_cas": [
            "/path/to/first/client/CA/root/certificate.pem",
            "/path/to/second/client/CA/root/certificate.pem",
            "/path/to/third/client/CA/root/certificate.pem"
        ]
    },
    "allowed_hosts": [
        "localhost",
        "127.0.0.1",
        "[::1]"
    ],
    "attest": {
        "trusted_provider_public_key": "/path/to/mock/provider-public-key.pem",
        "targets": [
            {
                "name": "RUP-workload-1",
                "mechanism": "enroll",
                "freshness_kind": "present-nonce"
            },
            {
                "name": "RUP-workload-2",
                "mechanism": "retrieve",
                "freshness_kind": "present-epoch",
                "epoch_marker": "deployment-epoch-1"
            }
        ]
    },
    "healthcheck_password": "xyzzy",
    "rate_limit": 150,
    "timeout": 30,
    "log_file": "/path/to/log.file",
    "wire_log": "/path/to/wire.log"
}`

// sampleConfig outputs a sample configuration file.
func sampleConfig() {
	fmt.Println(sample)
}
