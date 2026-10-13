# est

[![GoDoc](https://godoc.org/github.com/globalsign/est?status.svg)](https://godoc.org/github.com/globalsign/est)
[![Build Status](https://github.com/globalsign/est/actions/workflows/go.yml/badge.svg)](https://github.com/globalsign/est/actions/workflows/go.yml)
[![Go Report Card](https://goreportcard.com/badge/github.com/globalsign/est)](https://goreportcard.com/report/github.com/globalsign/est)

An implementation of the Enrollment over Secure Transport (EST) certificate
enrollment protocol as defined by [RFC7030](https://tools.ietf.org/html/rfc7030).

The implementation provides:

 * An EST client library;
 * An EST client command line utility using the client library; and
 * An EST server which can be used for testing and development purposes.

The implementation is intended to be mostly feature-complete, including
support for:

 * The optional `/csrattrs` and `/serverkeygen` operations, with support for
   server-generated private keys returned with or without additional
   encryption
 * The optional additional path segment
 * Optional HTTP-based client authentication on top of certificate-based
   TLS authentication

In addition, a non-standard operation is implemented enabling EST-like
enrollment using the privacy preserving protocol for distributing credentials
for keys on a Trusted Platform Module (TPM) 2.0 device, as described in Part 1,
section 24 of the Trusted Platform Module 2.0 Library specification.

## Installation

    go install github.com/globalsign/est/cmd/estserver@latest
    go install github.com/globalsign/est/cmd/estclient@latest

## Quickstart

### Starting the server

When started with no configuration file, the EST server listens on
localhost:8443 and generates a random, transient Certificate Authority (CA)
which can be used for testing:

    user@host:$ estserver &
    [1] 62405

Refer to the documentation for more details on using a configuration file.

### Getting the CA certificates

Because we're using a random, transient CA, we must retrieve the CA certificates
in insecure mode to establish an explicit trust anchor for subsequent EST
operations. Since we only need the root CA certificate to establish a trust
anchor, we use the `-rootout` flag:

    user@host:$ estclient cacerts -server localhost:8443 -insecure -rootout -out anchor.pem

We will also obtain and store the full CA certificates chain, since we'll use
it shortly to demonstrate reenrollment. Since we now have an explicit trust
anchor, we can use it instead of the `-insecure` option. Since we're storing
the full chain, we don't use the `-rootout` option here:

    user@host:$ estclient cacerts -server localhost:8443 -explicit anchor.pem -out cacerts.pem

### Enrolling with an existing private key

First we generate a new private key, here using openssl:

    user@host:$ openssl genrsa 4096 > key.pem
    Generating RSA private key, 4096 bit long modulus
    .................+++
    .............+++
    e is 65537 (0x10001)

Then we generate a PKCS#10 certificate signing request, and enroll using the
explicit trust anchor we previously obtained:

    user@host:$ estclient csr -key key.pem -cn 'John Doe' -emails 'john@doe.com' -out csr.pem
    user@host:$ estclient enroll -server localhost:8443 -explicit anchor.pem -csr csr.pem -out cert.pem

Using a configuration file, we can enroll with a private key resident on a
hardware module, such as a hardware security module (HSM) or a Trusted Platform
Module 2.0 (TPM) device. Refer to the documentation for more details.

### Enforcing proof of possession

If one would like to enforce the PoP as defined in [RFC 7030 section 3.5](https://www.rfc-editor.org/rfc/rfc7030#section-3.5), we have to pass the signing key to EST client so it can include the challenge password in the CSR and then sign it once again.  

    user@host:$ estclient enroll -server localhost:8443 -explicit anchor.pem -csr csr.pem -signingkey key.pem -out cert.pem

Reminder,

* the `tls-unique` value mentioned in RFC 7030 is specific to TLS v1.2
* the options `-key` and `-signingkey` are not necessarily the same
  * `-key` is used for mTLS purpose like during an initial enroll
  * `-signingkey` is the key signing the CSR and therefore the one to be enrolled

### Enrolling with a server-generated private key

If we're unable or unwilling to create our own private key, the EST server can
generate one for us, and return it along with our certificate:

    user@host:$ estclient serverkeygen -server localhost:8443 -explicit anchor.pem -cn 'Jane Doe' -out cert.pem -keyout key.pem

Note that we can omit the `-csr` option when enrolling and the EST client can
dynamically generate a CSR for us using fields passed at the command line and
the private key we specified, or an automatically-generated ephemeral private
key if we are requesting server-side private key generation.

### Reenrolling

Whichever way we generated our private key, we can now use it to reenroll.

To reenroll a previously obtained certificate, we must use it to authenticate
ourselves during the TLS handshake with the EST server. Since our random,
transient CA uses an intermediate CA certificate, we must provide a chain of
certificates to the EST client, or the TLS handshake may fail.

Although providing the root CA certificate is optional for a TLS handshake,
the simplest option is to provide the certificate we received along with the
full chain of CA certificates which we previously obtained. To do this, we
can just append those CA certificates to the certificate we received, and
use that chain to reenroll:

    user@host:$ cat cert.pem cacerts.pem >> certs.pem
    user@host:$ estclient reenroll -server localhost:8443 -explicit anchor.pem -key key.pem -certs certs.pem -out newcert.pem

Note that when we omit the `-csr` option when reenrolling, the EST client
automatically generates a CSR for us by copying the subject field and subject
alternative name extension from the certificate we're renewing.

## Attested credential acquisition (TACRA)

This fork adds the three resources of
[draft-novak-lamps-tacra-est](https://datatracker.ietf.org/doc/draft-novak-lamps-tacra-est/)
to the server and to the client library: an Attester in a TEE obtains a
credential by proving, with its Evidence, that it is the workload the
Relying Party expects, in one of two modes.

| Resource | Method and request | Response |
|---|---|---|
| `/.well-known/est/attest-initiate` | `GET`, query `target` and `credential_type`; `Accept: application/est-attest-initiate+json` | the Freshness Kind of the Target, a Handle when the kind is `present-*`, the acceptable Evidence formats and key algorithms |
| `/.well-known/est/attest-enroll` | `POST application/est-attest-enroll+json`: a CSR and Evidence bound to it | the certificate, `application/pkcs7-mime` base64 (as simpleenroll) |
| `/.well-known/est/attest-retrieve` | `POST application/est-attest-retrieve+json`: a CEK public key and Evidence bound to it | `application/est-attest-bundle+json`: the credential in a container sealed to the CEK |

Every request is checked against the draft's syntax before anything else
(`attest_syntax.go`); a request the draft does not describe is refused
with 400 and a reason. The server runs with one of two backends.

### The mock backend: a mock CA, a mock TEE and a mock Verifier

For development and tests. The configuration names the Targets the CAS
serves, each with its mechanism and Freshness Kind, and the public key of
the mock TEE provider whose Evidence the mock Verifier accepts:

    user@host:$ openssl ecparam -name prime256v1 -genkey -noout -out provider.key
    user@host:$ openssl pkey -in provider.key -pubout -out provider.pub
    user@host:$ cat estserver.json
    {
        "attest": {
            "trusted_provider_public_key": "provider.pub",
            "targets": [
                { "name": "https://db.example", "mechanism": "enroll", "freshness_kind": "present-nonce", "credential_types": ["x509"] },
                { "name": "https://ledger.example", "mechanism": "retrieve", "freshness_kind": "absent-timestamp", "max_age": 120, "credential_types": ["api-key", "x509"] }
            ]
        }
    }
    user@host:$ estserver -config estserver.json &

`estserver -sampleconfig` prints a complete sample. Without a `mock_ca`
section the CA is transient, and without a `tls` section the server listens
on port 8443 with a transient certificate, as in the Quickstart. The first
leg of an acquisition is a `GET`:

    user@host:$ curl -sk -H "Accept: application/est-attest-initiate+json" \
        "https://localhost:8443/.well-known/est/attest-initiate?target=https://db.example&credential_type=x509"
    {"freshness_kind":"present-nonce","handle":"SGqaUOg9ylgU9U51os-mt05bvO9_miwNAdJqU8Tzk64","expires_in":300,"acceptable_evidence":["application/eat+cwt; eat_profile=\"https://twi.confidentialcomputing.io/tacra-est-mock/1.0.0\""],"acceptable_csk":["ecdsa-p256-sha256"],"mode":"enroll"}

    user@host:$ curl -sk -H "Accept: application/est-attest-initiate+json" \
        "https://localhost:8443/.well-known/est/attest-initiate?target=https://ledger.example&credential_type=x509"
    {"freshness_kind":"absent-timestamp","max_age":120,"acceptable_evidence":["application/eat+cwt; eat_profile=\"https://twi.confidentialcomputing.io/tacra-est-mock/1.0.0\""],"acceptable_cek":["ECDH-P256+HKDF-SHA256+A256GCM"],"mode":"retrieve"}

A Target the configuration does not name is refused with 403. The second
leg needs Evidence: the library makes the mock TEE's (`est.NewMockEvidence`,
signed with `provider.key`) and the client sends it (`est.Client`'s
`InitiateRemoteAttestation`, `EnrollCredential` and `RetrieveCredential`).
`attest_mock_flow_test.go` runs the whole path through the wire, for every
Freshness Kind, in Enrollment and in Retrieval, with the refusals a changed
input meets, and opens the Retrieval container to check the certificate, its
key and the CA chain it releases:

    user@host:$ go test -run TestMockFlow .
    ok      github.com/globalsign/est       0.438s

### The TACRA backend: deployed Verifiers and RRPs

For a deployment. With a `tacra` section the server has no CA of its own: it
is the CAS of the draft, an untrusted conduit between the Attester and the
Verifiers and RATS-unaware Relying Parties (RRPs) it is configured with.
`estserver.json.example` shows the shape; the keys are:

- `tls`: required, with `client_cas`; the resources are reached over mutual
  TLS.
- `tacra.client_cert`, `tacra.client_key`: this server's certificate on its
  calls to the Verifiers and the RRPs, which take only callers they know.
- `tacra.verifiers`: by name, `url`, `ca` (of its TLS certificate) and
  `provider`, the TSM report provider of the Evidence it appraises
  (`sev_guest`, `tdx_guest`).
- `tacra.rrps`: by name, `url`, `ca`, `mode` (`enroll` for a Credential
  Authority, `retrieve` for a Secret Vault), `rats_model` (`passport`: this
  server obtains the Attestation Results from the Verifier the RRP's policy
  names in `verifiers`; `background-check`: the RRP obtains them from the
  Evidence this server forwards).
- `tacra.targets`: each Target the server serves, and the RRP that provisions
  it.
- `tacra.acceptable_evidence`: the Evidence media types attest-initiate
  offers (`application/vnd.veraison.tsm-report+cbor` for SEV-SNP and TDX
  reports through configfs-tsm).
- `tacra.ca_certs`: the PEM chain served at `/cacerts`.
- `wire_log` (optional, at the top level): a file where every attest-*
  exchange is written as it crossed the wire, one JSON object per line.

The configuration is decoded strictly: an unknown member, or the mock
backend's `mock_ca` and `attest` sections beside `tacra`, is an error at
start. The backend's tests (`internal/tacra`) cover the wire syntax, the
binding, the sessions and the conduit in process, and the backend's answers
when a Verifier or an RRP cannot be reached; `internal/refvectors` checks the
library's messages against the vectors a reference implementation recorded
on Google Cloud SEV-SNP hardware.

## Formal model and measurements

`formal/` holds the ProVerif models of the credential-acquisition exchange
and the binding of TACRA Section 4.5, with the tool's output: the attacks
the binding of draft -00 admitted, the proofs with the binding in place, and
what each guarantee depends on, including where the Relying Party identifier
comes from and whether it is bound at all (`formal/README.md`).
`docs/measurements/` holds the measurements behind two sentences of the
drafts, with the runs they come from: how long a confidential VM takes to
produce fresh Evidence on AWS, Azure and Google Cloud, SEV-SNP and TDX
([report-rate.md](docs/measurements/report-rate.md)), and why a Freshness
Handle's lifetime has a floor
([handle-lifetime.md](docs/measurements/handle-lifetime.md));
`scripts/measure/` repeats them on a cloud account of your own.
