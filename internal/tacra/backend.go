// Package tacra is an EST server backend for attested credential acquisition (draft-novak-lamps-tacra-est) that
// talks to deployed components: Freshness Handles come from the RATS Relying Party (RRP) that will rely on the
// Evidence, a Credential Authority or a Secret Vault. For an RRP in the Passport model (the default) Evidence goes
// to a verifier the RRP takes and the Attestation Results go with the request to the RRP; for an RRP in the
// Background Check model the Evidence goes to the RRP, which asks the verifier itself (TACRA Goal 6; Mark Novak,
// TheBankster/rats-tacra#6: "the Verifier would be contacted by SV and CA in Background Check mode. For Passport
// mode, the interaction is driven by the CAS Server"). The Attester sees no difference. As the profile requires of an
// EST server, it mints no Handle, appraises neither Evidence nor Attestation Results, and authorizes nothing: the RRP
// decides.
package tacra

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/fxamacker/cbor/v2"
	"github.com/globalsign/est"
	"github.com/globalsign/pemfile"
)

// Config is the backend's section of the EST server configuration.
type Config struct {
	// Verifiers by name: where this server obtains Attestation Results for an RRP in the Passport model, and the TSM
	// report provider whose Evidence each appraises. An RRP's policy names the verifiers it takes (RRP.Verifiers).
	Verifiers map[string]Verifier `json:"verifiers"`
	// ClientCert and ClientKey are this server's certificate on its calls to the RRPs and the verifiers, which take
	// only callers they know (mutual TLS, N23).
	ClientCert         string            `json:"client_cert,omitempty"`
	ClientKey          string            `json:"client_key,omitempty"`
	RRPs               map[string]RRP    `json:"rrps"`    // by name
	Targets            map[string]string `json:"targets"` // Target -> RRP name
	AcceptableEvidence []string          `json:"acceptable_evidence"`
	CACerts            string            `json:"ca_certs"` // PEM chain served at /cacerts
}

// Verifier is one verifier this server may ask.
type Verifier struct {
	URL      string `json:"url"`
	CA       string `json:"ca"`       // CA of its TLS certificate
	Provider string `json:"provider"` // the TSM report provider of the Evidence it appraises ("sev_guest", "tdx_guest")
}

// RRP is a Credential Authority or Secret Vault gateway.
type RRP struct {
	URL   string `json:"url"`
	CA    string `json:"ca"`     // CA of its TLS certificate
	RRPID string `json:"rrp_id"` // the identifier it binds; checked against its attest-initiate answers
	Mode  string `json:"mode"`   // "enroll" or "retrieve"
	// RATSModel: "passport" (the default), this server obtains the Attestation Results; "background-check", the
	// RRP does, from the Evidence this server forwards
	RATSModel string `json:"rats_model,omitempty"`
	// Verifiers names the verifiers whose Attestation Results the RRP takes, as its policy says (N24). In Passport
	// this server asks only these, the one for the Evidence's TSM provider, and refuses Evidence none of them
	// appraises; the RRP checks again that its own policy's verifier signed what it receives.
	Verifiers []string `json:"verifiers,omitempty"`
}

type session struct {
	target, credentialType, rrp, kind string
	expires                           time.Time
}

// Backend implements est.CA, est.AttestationCA and est.RawRetriever.
type Backend struct {
	cfg       Config
	cacerts   []*x509.Certificate
	verifiers map[string]*http.Client // by name
	rrps      map[string]*http.Client

	mu       sync.Mutex
	sessions map[string]session // present-* Handles returned by attest-initiate
}

// client is TLS 1.3 to a server certified by caPath, presenting this server's client certificate when one is
// configured.
func (c *Config) client(caPath string) (*http.Client, error) {
	pem, err := os.ReadFile(caPath)
	if err != nil {
		return nil, err
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(pem) {
		return nil, errors.New("tacra: no CA certificate in " + caPath)
	}
	tc := &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS13}
	if c.ClientCert != "" || c.ClientKey != "" {
		pair, err := tls.LoadX509KeyPair(c.ClientCert, c.ClientKey)
		if err != nil {
			return nil, fmt.Errorf("tacra: client certificate: %w", err)
		}
		tc.Certificates = []tls.Certificate{pair}
	}
	return &http.Client{Timeout: 60 * time.Second, Transport: &http.Transport{TLSClientConfig: tc}}, nil
}

// New builds the backend from its configuration.
func New(cfg Config) (*Backend, error) {
	b := &Backend{cfg: cfg, rrps: map[string]*http.Client{}, verifiers: map[string]*http.Client{}, sessions: map[string]session{}}
	var err error
	for name, v := range cfg.Verifiers {
		if v.URL == "" || v.Provider == "" {
			return nil, fmt.Errorf("tacra: verifier %s: url and provider are required", name)
		}
		if b.verifiers[name], err = cfg.client(v.CA); err != nil {
			return nil, err
		}
	}
	for name, r := range cfg.RRPs {
		if r.Mode != est.MechanismEnroll && r.Mode != est.MechanismRetrieve {
			return nil, fmt.Errorf("tacra: RRP %s: mode must be enroll or retrieve", name)
		}
		if r.RATSModel != "" && r.RATSModel != passport && r.RATSModel != backgroundCheck {
			return nil, fmt.Errorf("tacra: RRP %s: rats_model must be passport or background-check", name)
		}
		if r.RATSModel != backgroundCheck && len(r.Verifiers) == 0 {
			return nil, fmt.Errorf("tacra: RRP %s: in Passport this server asks a verifier the RRP takes; it names none", name)
		}
		for _, v := range r.Verifiers {
			if _, ok := cfg.Verifiers[v]; !ok {
				return nil, fmt.Errorf("tacra: RRP %s names unknown verifier %s", name, v)
			}
		}
		if b.rrps[name], err = cfg.client(r.CA); err != nil {
			return nil, err
		}
	}
	for t, name := range cfg.Targets {
		if _, ok := cfg.RRPs[name]; !ok {
			return nil, fmt.Errorf("tacra: Target %s names unknown RRP %s", t, name)
		}
	}
	if len(cfg.AcceptableEvidence) == 0 {
		return nil, errors.New("tacra: acceptable_evidence is empty")
	}
	if cfg.CACerts != "" {
		if b.cacerts, err = pemfile.ReadCerts(cfg.CACerts); err != nil {
			return nil, err
		}
	}
	return b, nil
}

// httpError carries an HTTP status to the EST server's error writer.
type httpError struct {
	status int
	msg    string
}

func (e *httpError) Error() string   { return e.msg }
func (e *httpError) StatusCode() int { return e.status }
func (e *httpError) RetryAfter() int { return 0 }

func fail(status int, format string, a ...any) error {
	return &httpError{status, fmt.Sprintf(format, a...)}
}

var errClassic = fail(http.StatusNotImplemented, "this EST server provisions credentials only through attest-* resources")

// Classic EST resources are not offered: an attested request is never answered by a classic operation.

func (b *Backend) CACerts(context.Context, string, *http.Request) ([]*x509.Certificate, error) {
	if len(b.cacerts) == 0 {
		return nil, errClassic
	}
	return b.cacerts, nil
}
func (b *Backend) CSRAttrs(context.Context, string, *http.Request) (est.CSRAttrs, error) {
	return est.CSRAttrs{}, nil
}
func (b *Backend) Enroll(context.Context, *x509.CertificateRequest, string, *http.Request) (*x509.Certificate, error) {
	return nil, errClassic
}
func (b *Backend) Reenroll(context.Context, *x509.Certificate, *x509.CertificateRequest, string, *http.Request) (*x509.Certificate, error) {
	return nil, errClassic
}
func (b *Backend) ServerKeyGen(context.Context, *x509.CertificateRequest, string, *http.Request) (*x509.Certificate, []byte, error) {
	return nil, nil, errClassic
}
func (b *Backend) TPMEnroll(context.Context, *x509.CertificateRequest, []*x509.Certificate, []byte, []byte, string, *http.Request) ([]byte, []byte, []byte, error) {
	return nil, nil, nil, errClassic
}

func b64u(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

// post sends v as JSON to an RRP gateway and decodes the answer into out, passing the gateway's refusal through.
func (b *Backend) post(ctx context.Context, rrp, path string, v, out any) ([]byte, error) {
	body, _ := json.Marshal(v)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, strings.TrimRight(b.cfg.RRPs[rrp].URL, "/")+path, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := b.rrps[rrp].Do(req)
	if err != nil {
		return nil, fail(http.StatusBadGateway, "RRP %s unreachable", rrp)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode != http.StatusOK {
		var e struct{ Error, Detail string }
		_ = json.Unmarshal(raw, &e)
		return nil, fail(resp.StatusCode, "RRP %s: %s: %s", rrp, e.Error, e.Detail)
	}
	if out != nil {
		if err := json.Unmarshal(raw, out); err != nil {
			return nil, fail(http.StatusBadGateway, "RRP %s: malformed answer", rrp)
		}
	}
	return raw, nil
}

func (b *Backend) route(target string) (string, RRP, error) {
	name, ok := b.cfg.Targets[target]
	if !ok {
		return "", RRP{}, fail(http.StatusForbidden, "unsupported Target")
	}
	return name, b.cfg.RRPs[name], nil
}

// InitiateRemoteAttestation obtains the Freshness Kind and Handle from the RRP that serves the Target.
func (b *Backend) InitiateRemoteAttestation(ctx context.Context, target, credentialType, aps string, r *http.Request) (*est.AttestationInitiateResponse, error) {
	name, rrp, err := b.route(target)
	if err != nil {
		return nil, err
	}
	var g struct {
		FreshnessKind string   `json:"freshness_kind"`
		Handle        string   `json:"handle"`
		RRPID         string   `json:"rrp_id"`
		ExpiresIn     int      `json:"expires_in"`
		MaxAge        int      `json:"max_age"`
		Mode          string   `json:"mode"`
		AcceptableCSK []string `json:"acceptable_csk"`
		AcceptableCEK []string `json:"acceptable_cek"`
	}
	if _, err := b.post(ctx, name, "/tacra/v1/initiate", map[string]string{"target": target, "credential_type": credentialType}, &g); err != nil {
		return nil, err
	}
	if g.RRPID != rrp.RRPID || g.Mode != rrp.Mode {
		return nil, fail(http.StatusBadGateway, "RRP %s answered as %s/%s, configured as %s/%s", name, g.RRPID, g.Mode, rrp.RRPID, rrp.Mode)
	}
	handle, err := base64.RawURLEncoding.DecodeString(g.Handle)
	if err != nil {
		return nil, fail(http.StatusBadGateway, "RRP %s: Handle is not base64url", name)
	}
	if len(handle) > 0 {
		b.mu.Lock()
		now := time.Now()
		for k, s := range b.sessions {
			if now.After(s.expires) {
				delete(b.sessions, k)
			}
		}
		b.sessions[hex.EncodeToString(handle)] = session{target, credentialType, name, g.FreshnessKind,
			now.Add(time.Duration(g.ExpiresIn) * time.Second)}
		b.mu.Unlock()
	}
	return &est.AttestationInitiateResponse{FreshnessKind: g.FreshnessKind, Handle: handle, RRPID: g.RRPID,
		ExpiresIn: g.ExpiresIn, MaxAge: g.MaxAge, AcceptableEvidence: b.cfg.AcceptableEvidence,
		RequiredBindings: []string{est.BindingInput}, AcceptableCSK: g.AcceptableCSK, AcceptableCEK: g.AcceptableCEK,
		Mechanism: g.Mode}, nil
}

// correlate refuses a second leg that does not belong to the attest-initiate that returned its Handle.
func (b *Backend) correlate(kind string, handle []byte, target, credentialType string) error {
	if kind != est.FreshnessPresentNonce && kind != est.FreshnessPresentEpoch {
		return nil // no Handle was returned; the RRP checks the freshness element
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	key := hex.EncodeToString(handle)
	s, ok := b.sessions[key]
	if !ok || time.Now().After(s.expires) {
		return fail(http.StatusConflict, "no attest-initiate returned this Handle, or it expired")
	}
	if s.target != target || s.credentialType != credentialType || s.kind != kind {
		return fail(http.StatusForbidden, "Target, Credential Type or Freshness Kind differ from the attest-initiate")
	}
	if kind == est.FreshnessPresentNonce {
		delete(b.sessions, key)
	}
	return nil
}

func (b *Backend) profile(p string) (string, error) {
	if p == "" {
		return b.cfg.AcceptableEvidence[0], nil
	}
	if !slices.Contains(b.cfg.AcceptableEvidence, p) {
		return "", fail(http.StatusUnsupportedMediaType, "Evidence format %q is not accepted", p)
	}
	return p, nil
}

// verifierFor picks, among the verifiers the RRP takes, the one for the Evidence's TSM provider (N24: the RRP's
// configuration chooses the verifier; the Evidence only picks among those, and there is no default for the rest).
func (b *Backend) verifierFor(rrpName string, rrp RRP, evidence []byte) (string, error) {
	var t struct {
		Provider string `cbor:"provider"`
	}
	provider := ""
	if cbor.Unmarshal(evidence, &t) == nil {
		provider = strings.TrimSpace(t.Provider)
	}
	for _, name := range rrp.Verifiers {
		if v := b.cfg.Verifiers[name]; v.Provider == provider {
			return name, nil
		}
	}
	return "", fail(http.StatusForbidden, "none of the verifiers RRP %s takes appraises Evidence of provider %q", rrpName, provider)
}

// verify obtains Attestation Results from the named verifier: a challenge-response session whose nonce is the
// binding value, computed with the RRP's identifier, and the Evidence. It does not appraise the result; the RRP does.
func (b *Backend) verify(ctx context.Context, verifier string, evidence []byte, profile string, nonce []byte) (string, error) {
	base, vc := strings.TrimRight(b.cfg.Verifiers[verifier].URL, "/"), b.verifiers[verifier]
	q := url.Values{"nonce": {base64.URLEncoding.EncodeToString(nonce)}}
	req, _ := http.NewRequestWithContext(ctx, http.MethodPost, base+"/challenge-response/v1/newSession?"+q.Encode(), nil)
	resp, err := vc.Do(req)
	if err != nil {
		return "", fail(http.StatusServiceUnavailable, "verifier unavailable")
	}
	resp.Body.Close()
	loc := resp.Header.Get("Location")
	if resp.StatusCode != http.StatusCreated || loc == "" {
		return "", fail(http.StatusServiceUnavailable, "verifier refused a session: HTTP %d", resp.StatusCode)
	}
	if !strings.HasPrefix(loc, "http") {
		loc = base + "/challenge-response/v1/" + strings.TrimPrefix(loc, "/")
	}
	defer func() {
		del, _ := http.NewRequest(http.MethodDelete, loc, nil)
		if r, err := vc.Do(del); err == nil {
			r.Body.Close()
		}
	}()
	req, _ = http.NewRequestWithContext(ctx, http.MethodPost, loc, bytes.NewReader(evidence))
	req.Header.Set("Content-Type", profile)
	req.Header.Set("Accept", "application/vnd.veraison.challenge-response-session+json")
	resp, err = vc.Do(req)
	if err != nil {
		return "", fail(http.StatusServiceUnavailable, "verifier unavailable")
	}
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	resp.Body.Close()
	var s struct {
		Status string `json:"status"`
		Result string `json:"result"`
	}
	if json.Unmarshal(raw, &s) != nil || s.Status != "complete" || s.Result == "" {
		return "", fail(http.StatusForbidden, "the verifier produced no Attestation Results (HTTP %d)", resp.StatusCode)
	}
	return s.Result, nil
}

// The RATS models an RRP may run in (RRP.RATSModel).
const (
	passport        = "passport"
	backgroundCheck = "background-check"
)

type secondLeg struct {
	FreshnessKind  string `json:"freshness_kind"`
	Target         string `json:"target"`
	CredentialType string `json:"credential_type"`
	Handle         string `json:"handle,omitempty"`
	CredentialHint string `json:"credential_hint,omitempty"`
	EAR            string `json:"ear,omitempty"`      // Passport: the verifier's Attestation Results
	Evidence       string `json:"evidence,omitempty"` // Background Check: the Attester's Evidence, unopened
	Profile        string `json:"profile,omitempty"`  // Background Check: its media type
}

func hint(h *string) string {
	if h == nil {
		return ""
	}
	return *h
}

func (b *Backend) forward(ctx context.Context, mode, kind, target, credentialType string, handle, evidence []byte,
	profile string, hintp *string, subject []byte) (string, RRP, secondLeg, error) {
	name, rrp, err := b.route(target)
	if err != nil {
		return "", RRP{}, secondLeg{}, err
	}
	if rrp.Mode != mode {
		return "", RRP{}, secondLeg{}, fail(http.StatusForbidden, "the Target is provisioned by %s, not %s", rrp.Mode, mode)
	}
	if err := b.correlate(kind, handle, target, credentialType); err != nil {
		return "", RRP{}, secondLeg{}, err
	}
	p, err := b.profile(profile)
	if err != nil {
		return "", RRP{}, secondLeg{}, err
	}
	leg := secondLeg{FreshnessKind: kind, Target: target, CredentialType: credentialType, CredentialHint: hint(hintp)}
	if rrp.RATSModel == backgroundCheck {
		// the RRP asks the verifier, with the binding value it recomputes; this server does not
		leg.Evidence, leg.Profile = b64u(evidence), p
	} else {
		v, err := b.verifierFor(name, rrp, evidence)
		if err != nil {
			return "", RRP{}, secondLeg{}, err
		}
		nonce := bindingValue(handle, target, rrp.RRPID, subject)
		if leg.EAR, err = b.verify(ctx, v, evidence, p, nonce); err != nil {
			return "", RRP{}, secondLeg{}, err
		}
	}
	if len(handle) > 0 {
		leg.Handle = b64u(handle)
	}
	return name, rrp, leg, nil
}

// EnrollCredential forwards Evidence to a verifier the RRP takes, then the CSR and Attestation Results to the
// Credential Authority;
// in Background Check, the CSR and the Evidence to the Credential Authority.
func (b *Backend) EnrollCredential(ctx context.Context, req *est.AttestedEnrollmentRequest, aps string, r *http.Request) (*x509.Certificate, error) {
	name, _, leg, err := b.forward(ctx, est.MechanismEnroll, req.FreshnessKind, req.Target, req.CredentialType,
		req.Handle, req.Evidence, req.Profile, req.CredentialHint, req.CSR)
	if err != nil {
		return nil, err
	}
	var out struct {
		CertificateChain []string `json:"certificate_chain"`
	}
	if _, err := b.post(ctx, name, "/tacra/v1/enroll", struct {
		secondLeg
		CSR string `json:"csr"`
	}{leg, b64u(req.CSR)}, &out); err != nil {
		return nil, err
	}
	if len(out.CertificateChain) == 0 {
		return nil, fail(http.StatusBadGateway, "RRP %s returned no certificate", name)
	}
	der, err := base64.RawURLEncoding.DecodeString(out.CertificateChain[0])
	if err != nil {
		return nil, fail(http.StatusBadGateway, "RRP %s: certificate is not base64url", name)
	}
	return x509.ParseCertificate(der)
}

// RetrieveCredential is not used: RetrieveCredentialRaw returns the Vault's container unchanged.
func (b *Backend) RetrieveCredential(context.Context, *est.AttestedRetrievalRequest, string, *http.Request) (*est.EncryptedCredentialBundle, error) {
	return nil, fail(http.StatusInternalServerError, "RetrieveCredentialRaw serves attest-retrieve")
}

// RetrieveCredentialRaw forwards Evidence to a verifier the RRP takes, then CEKpub and the Attestation Results to the
// Secret Vault
// (in Background Check, CEKpub and the Evidence), and returns the Vault's encrypted container unchanged.
func (b *Backend) RetrieveCredentialRaw(ctx context.Context, req *est.AttestedRetrievalRequest, aps string, r *http.Request) ([]byte, error) {
	name, _, leg, err := b.forward(ctx, est.MechanismRetrieve, req.FreshnessKind, req.Target, req.CredentialType,
		req.Handle, req.Evidence, req.Profile, req.CredentialHint, req.CEKPub)
	if err != nil {
		return nil, err
	}
	return b.post(ctx, name, "/tacra/v1/retrieve", struct {
		secondLeg
		CEKPub string `json:"cek_pub"`
	}{leg, b64u(req.CEKPub)}, nil)
}
