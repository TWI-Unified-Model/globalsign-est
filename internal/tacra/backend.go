// Package tacra is an EST server backend for attested credential acquisition (draft-novak-lamps-tacra-est) that
// talks to deployed components: Freshness Handles come from the RATS Relying Party (RRP) that will rely on the
// Evidence, Evidence goes to a Veraison verification service (Passport model), and the Attestation Results go with
// the request to that RRP, a Credential Authority or a Secret Vault. As the profile requires of an EST server, it
// mints no Handle, appraises neither Evidence nor Attestation Results, and authorizes nothing: the RRP decides.
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

	"github.com/globalsign/est"
	"github.com/globalsign/pemfile"
)

// Config is the backend's section of the EST server configuration.
type Config struct {
	Veraison struct {
		URL string `json:"url"`
		CA  string `json:"ca"`
	} `json:"veraison"`
	RRPs               map[string]RRP    `json:"rrps"`    // by name
	Targets            map[string]string `json:"targets"` // Target -> RRP name
	AcceptableEvidence []string          `json:"acceptable_evidence"`
	CACerts            string            `json:"ca_certs"` // PEM chain served at /cacerts
}

// RRP is a Credential Authority or Secret Vault gateway.
type RRP struct {
	URL   string `json:"url"`
	CA    string `json:"ca"`     // CA of its TLS certificate
	RRPID string `json:"rrp_id"` // the identifier it binds; checked against its attest-initiate answers
	Mode  string `json:"mode"`   // "enroll" or "retrieve"
}

type session struct {
	target, credentialType, rrp, kind string
	expires                           time.Time
}

// Backend implements est.CA, est.AttestationCA and est.RawRetriever.
type Backend struct {
	cfg      Config
	cacerts  []*x509.Certificate
	veraison *http.Client
	rrps     map[string]*http.Client

	mu       sync.Mutex
	sessions map[string]session // present-* Handles returned by attest-initiate
}

func client(caPath string) (*http.Client, error) {
	pem, err := os.ReadFile(caPath)
	if err != nil {
		return nil, err
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(pem) {
		return nil, errors.New("tacra: no CA certificate in " + caPath)
	}
	return &http.Client{Timeout: 60 * time.Second, Transport: &http.Transport{
		TLSClientConfig: &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12}}}, nil
}

// New builds the backend from its configuration.
func New(cfg Config) (*Backend, error) {
	b := &Backend{cfg: cfg, rrps: map[string]*http.Client{}, sessions: map[string]session{}}
	var err error
	if b.veraison, err = client(cfg.Veraison.CA); err != nil {
		return nil, err
	}
	for name, r := range cfg.RRPs {
		if r.Mode != est.MechanismEnroll && r.Mode != est.MechanismRetrieve {
			return nil, fmt.Errorf("tacra: RRP %s: mode must be enroll or retrieve", name)
		}
		if b.rrps[name], err = client(r.CA); err != nil {
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

// verify obtains Attestation Results from Veraison: a challenge-response session whose nonce is the binding value,
// computed with the RRP's identifier, and the Evidence. It does not appraise the result; the RRP does.
func (b *Backend) verify(ctx context.Context, evidence []byte, profile string, nonce []byte) (string, error) {
	base := strings.TrimRight(b.cfg.Veraison.URL, "/")
	q := url.Values{"nonce": {base64.URLEncoding.EncodeToString(nonce)}}
	req, _ := http.NewRequestWithContext(ctx, http.MethodPost, base+"/challenge-response/v1/newSession?"+q.Encode(), nil)
	resp, err := b.veraison.Do(req)
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
		if r, err := b.veraison.Do(del); err == nil {
			r.Body.Close()
		}
	}()
	req, _ = http.NewRequestWithContext(ctx, http.MethodPost, loc, bytes.NewReader(evidence))
	req.Header.Set("Content-Type", profile)
	req.Header.Set("Accept", "application/vnd.veraison.challenge-response-session+json")
	resp, err = b.veraison.Do(req)
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

type secondLeg struct {
	FreshnessKind  string `json:"freshness_kind"`
	Target         string `json:"target"`
	CredentialType string `json:"credential_type"`
	Handle         string `json:"handle,omitempty"`
	CredentialHint string `json:"credential_hint,omitempty"`
	EAR            string `json:"ear"`
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
	nonce := est.BindingDigest(handle, rrp.RRPID, target, subject)
	ear, err := b.verify(ctx, evidence, p, nonce)
	if err != nil {
		return "", RRP{}, secondLeg{}, err
	}
	leg := secondLeg{FreshnessKind: kind, Target: target, CredentialType: credentialType, CredentialHint: hint(hintp), EAR: ear}
	if len(handle) > 0 {
		leg.Handle = b64u(handle)
	}
	return name, rrp, leg, nil
}

// EnrollCredential forwards Evidence to Veraison, then the CSR and Attestation Results to the Credential Authority.
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

// RetrieveCredentialRaw forwards Evidence to Veraison, then CEKpub and the Attestation Results to the Secret Vault,
// and returns the Vault's encrypted container unchanged.
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
