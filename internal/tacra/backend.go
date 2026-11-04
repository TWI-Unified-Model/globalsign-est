// Package tacra is an EST server backend for attested credential acquisition (draft-novak-lamps-tacra-est) that
// talks to deployed components: Freshness Handles come from the RATS Relying Party that will rely on the
// Evidence, a Credential Authority or a Secret Vault. For a RATS Relying Party in the Passport model (the default) Evidence goes
// to a verifier the RATS Relying Party takes and the Attestation Results go with the request to the RATS Relying Party; for a RATS Relying Party in the
// Background Check model the Evidence goes to the RATS Relying Party, which asks the verifier itself (TACRA Goal 6; Mark Novak,
// TheBankster/rats-tacra#6: "the Verifier would be contacted by SV and CA in Background Check mode. For Passport
// mode, the interaction is driven by the CAS Server"). The Attester sees no difference. As the profile requires of an
// EST server, it mints no Handle, appraises neither Evidence nor Attestation Results, and authorizes nothing: the RATS Relying Party
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
	// Verifiers by name: where this server obtains Attestation Results for a RATS Relying Party in the Passport model, and the TSM
	// report provider whose Evidence each appraises. An RATS Relying Party's policy names the verifiers it takes (RATS Relying Party.Verifiers).
	Verifiers map[string]Verifier `json:"verifiers"`
	// ClientCert and ClientKey are this server's certificate on its calls to the RATS Relying Parties and the verifiers, which take
	// only callers they know (mutual TLS, N23).
	ClientCert         string                  `json:"client_cert,omitempty"`
	ClientKey          string                  `json:"client_key,omitempty"`
	RelyingParties     map[string]RelyingParty `json:"rrps"`    // by name
	Targets            map[string]string       `json:"targets"` // Target -> RATS Relying Party name
	AcceptableEvidence []string                `json:"acceptable_evidence"`
	CACerts            string                  `json:"ca_certs"` // PEM chain returned at /cacerts
	// ConduitLog is where this server records what it does as the untrusted conduit of a drill (RATS Relying Party.ConduitAttack),
	// one line per act, for the bench's verdict to read; empty: standard error.
	ConduitLog string `json:"conduit_log,omitempty"`
}

// Verifier is one verifier this server may ask.
type Verifier struct {
	URL      string `json:"url"`
	CA       string `json:"ca"`       // CA of its TLS certificate
	Provider string `json:"provider"` // the TSM report provider of the Evidence it appraises ("sev_guest", "tdx_guest")
}

// RATS Relying Party is a Credential Authority or Secret Vault gateway.
type RelyingParty struct {
	URL  string `json:"url"`
	CA   string `json:"ca"`   // CA of its TLS certificate
	Mode string `json:"mode"` // "enroll" or "retrieve"
	// RATSModel: "passport" (the default), this server obtains the Attestation Results; "background-check", the
	// RATS Relying Party does, from the Evidence this server forwards
	RATSModel string `json:"rats_model,omitempty"`
	// Verifiers names the verifiers whose Attestation Results the RATS Relying Party takes, as its policy says (N24). In Passport
	// this server asks only these, the one for the Evidence's TSM provider, and refuses Evidence none of them
	// appraises; the RATS Relying Party checks again that its own policy's verifier signed what it receives.
	Verifiers []string `json:"verifiers,omitempty"`
	// ConduitAttack names a drill of the bench in which this server acts as TACRA's untrusted conduit against the RATS Relying Party.
	// "verifier": in Passport, the Attestation Results the verifier returned are signed again with a key of this
	// server's own before they go to the RATS Relying Party, as a Verifier of the conduit's own would have signed them; the RATS Relying Party is
	// expected to refuse them, none of the verifiers its policy takes having signed them (conduit.go).
	ConduitAttack string `json:"conduit_attack,omitempty"`
}

type session struct {
	target, credentialType, hint, relyingParty, kind string
	expires                                          time.Time
}

// Backend implements est.CA, est.AttestationCA and est.RawRetriever.
type Backend struct {
	cfg            Config
	cacerts        []*x509.Certificate
	verifiers      map[string]*http.Client // by name
	relyingParties map[string]*http.Client
	conduit        *conduit // the attacking conduit of a drill, when a RATS Relying Party entry names one

	mu sync.Mutex
	// present-* Handles returned by attest-initiate, by Handle: a present-nonce Handle is one Target's, but a
	// present-epoch Handle is the epoch, which every Target of the deployment shares, so it keeps a session per Target
	// and Credential Type that asked
	sessions map[string][]session
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
	b := &Backend{cfg: cfg, relyingParties: map[string]*http.Client{}, verifiers: map[string]*http.Client{}, sessions: map[string][]session{}}
	var err error
	for name, v := range cfg.Verifiers {
		if v.URL == "" || v.Provider == "" {
			return nil, fmt.Errorf("tacra: verifier %s: url and provider are required", name)
		}
		if b.verifiers[name], err = cfg.client(v.CA); err != nil {
			return nil, err
		}
	}
	for name, r := range cfg.RelyingParties {
		if r.Mode != est.MechanismEnroll && r.Mode != est.MechanismRetrieve {
			return nil, fmt.Errorf("tacra: RATS Relying Party %s: mode must be enroll or retrieve", name)
		}
		if r.RATSModel != "" && r.RATSModel != passport && r.RATSModel != backgroundCheck {
			return nil, fmt.Errorf("tacra: RATS Relying Party %s: rats_model must be passport or background-check", name)
		}
		if r.RATSModel != backgroundCheck && len(r.Verifiers) == 0 {
			return nil, fmt.Errorf("tacra: RATS Relying Party %s: in Passport this server asks a verifier the RATS Relying Party takes; it names none", name)
		}
		for _, v := range r.Verifiers {
			if _, ok := cfg.Verifiers[v]; !ok {
				return nil, fmt.Errorf("tacra: RATS Relying Party %s names unknown verifier %s", name, v)
			}
		}
		if b.relyingParties[name], err = cfg.client(r.CA); err != nil {
			return nil, err
		}
		switch r.ConduitAttack {
		case "":
		case conduitVerifier:
			if r.RATSModel == backgroundCheck {
				return nil, fmt.Errorf("tacra: RATS Relying Party %s: conduit_attack %s is a Passport drill: in Background Check this server holds no Attestation Results", name, r.ConduitAttack)
			}
			if b.conduit == nil {
				if b.conduit, err = newConduit(cfg.ConduitLog); err != nil {
					return nil, err
				}
			}
		default:
			return nil, fmt.Errorf("tacra: RATS Relying Party %s: conduit_attack %q: the drills are %s", name, r.ConduitAttack, conduitVerifier)
		}
	}
	for t, name := range cfg.Targets {
		if _, ok := cfg.RelyingParties[name]; !ok {
			return nil, fmt.Errorf("tacra: Target %s names unknown RATS Relying Party %s", t, name)
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

// post sends v as JSON to a RATS Relying Party gateway and decodes the answer into out, passing the gateway's refusal through.
func (b *Backend) post(ctx context.Context, relyingParty, path string, v, out any) ([]byte, error) {
	body, _ := json.Marshal(v)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, strings.TrimRight(b.cfg.RelyingParties[relyingParty].URL, "/")+path, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := b.relyingParties[relyingParty].Do(req)
	if err != nil {
		return nil, fail(http.StatusBadGateway, "RATS Relying Party %s unreachable", relyingParty)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode != http.StatusOK {
		var e struct{ Error, Detail string }
		_ = json.Unmarshal(raw, &e)
		return nil, fail(resp.StatusCode, "RATS Relying Party %s: %s: %s", relyingParty, e.Error, e.Detail)
	}
	if out != nil {
		if err := json.Unmarshal(raw, out); err != nil {
			return nil, fail(http.StatusBadGateway, "RATS Relying Party %s: malformed answer", relyingParty)
		}
	}
	return raw, nil
}

// route is the RATS Relying Party of a Target. A Target this server does not support is a resource it does not have:
// 404 (the query is part of the target URI).
func (b *Backend) route(target string) (string, RelyingParty, error) {
	name, ok := b.cfg.Targets[target]
	if !ok {
		return "", RelyingParty{}, fail(http.StatusNotFound, "Target %q not supported", target)
	}
	return name, b.cfg.RelyingParties[name], nil
}

// gatewayInitiation is a RATS Relying Party gateway's answer to attest-initiate. No identifier of the RATS Relying
// Party is in it, or anywhere in this server.
type gatewayInitiation struct {
	FreshnessKind string   `json:"freshness_kind"`
	Handle        string   `json:"handle"`
	ExpiresIn     int      `json:"expires_in"`
	MaxAge        int      `json:"max_age"`
	Mode          string   `json:"mode"`
	AcceptableCSK []string `json:"acceptable_csk"`
	AcceptableCEK []string `json:"acceptable_cek"`
}

// InitiateRemoteAttestation obtains the Freshness Kind and Handle from the RATS Relying Party that serves the Target.
func (b *Backend) InitiateRemoteAttestation(ctx context.Context, target, credentialType, credentialHint, additionalPathSegment string, r *http.Request) (*est.AttestationInitiateResponse, error) {
	name, relyingParty, err := b.route(target)
	if err != nil {
		return nil, err
	}
	var g gatewayInitiation
	ask := map[string]string{"target": target, "credential_type": credentialType}
	if credentialHint != "" {
		ask["credential_hint"] = credentialHint // the Credential Hint of Initiate-Credential-Acquisition (TACRA 5.1), forwarded to the RATS Relying Party
	}
	if _, err := b.post(ctx, name, "/tacra/v1/initiate", ask, &g); err != nil {
		return nil, err
	}
	if g.Mode != relyingParty.Mode {
		return nil, fail(http.StatusBadGateway, "RATS Relying Party %s answered for %s, configured for %s", name, g.Mode, relyingParty.Mode)
	}
	resp, err := initiation(g, b.cfg.AcceptableEvidence)
	if err != nil {
		return nil, fail(http.StatusBadGateway, "RATS Relying Party %s: %v", name, err)
	}
	if len(resp.Handle) > 0 {
		b.remember(hex.EncodeToString(resp.Handle), session{target: target, credentialType: credentialType, hint: credentialHint,
			relyingParty: name, kind: g.FreshnessKind, expires: time.Now().Add(time.Duration(g.ExpiresIn) * time.Second)})
	}
	return resp, nil
}

// initiation is the attest-initiate response to a RATS Relying Party gateway's answer g: of g's members, those the CDDL of
// draft-novak-lamps-tacra-est (attestation-initiation-response) gives its Freshness Kind and mode,
// and no others. An answer that breaks the rule
// of the Handle (present-nonce and present-epoch carry one, the absent-* kinds none) is refused, so that the server
// sends no response the CDDL does not define.
func initiation(g gatewayInitiation, acceptableEvidence []string) (*est.AttestationInitiateResponse, error) {
	handle, err := base64.RawURLEncoding.DecodeString(g.Handle)
	if err != nil {
		return nil, errors.New("Handle is not base64url")
	}
	resp := &est.AttestationInitiateResponse{FreshnessKind: g.FreshnessKind, Mechanism: g.Mode,
		AcceptableEvidence: acceptableEvidence}
	switch g.FreshnessKind {
	case est.FreshnessPresentNonce, est.FreshnessPresentEpoch:
		if len(handle) == 0 {
			return nil, fmt.Errorf("%s without a Handle", g.FreshnessKind)
		}
		resp.Handle, resp.ExpiresIn = handle, g.ExpiresIn
	case est.FreshnessAbsentTimestamp, est.FreshnessAbsentEpoch, est.FreshnessAbsentNone:
		if len(handle) > 0 {
			return nil, fmt.Errorf("%s with a Handle", g.FreshnessKind)
		}
		if g.FreshnessKind == est.FreshnessAbsentTimestamp {
			resp.MaxAge = g.MaxAge
		}
	default:
		return nil, fmt.Errorf("unknown Freshness Kind %q", g.FreshnessKind)
	}
	switch g.Mode {
	case est.MechanismEnroll:
		resp.AcceptableCSK = g.AcceptableCSK
	case est.MechanismRetrieve:
		resp.AcceptableCEK = g.AcceptableCEK
	default:
		return nil, fmt.Errorf("unknown mode %q", g.Mode)
	}
	return resp, nil
}

// remember keeps the session of an attest-initiate under its Handle, in place of an earlier one for the same Target,
// Credential Type and kind, and forgets every expired session.
func (b *Backend) remember(key string, s session) {
	b.mu.Lock()
	defer b.mu.Unlock()
	now := time.Now()
	for k, ss := range b.sessions {
		live := ss[:0]
		for _, x := range ss {
			if !now.After(x.expires) && !(k == key && x.target == s.target && x.credentialType == s.credentialType && x.hint == s.hint && x.kind == s.kind) {
				live = append(live, x)
			}
		}
		if len(live) == 0 {
			delete(b.sessions, k)
		} else {
			b.sessions[k] = live
		}
	}
	b.sessions[key] = append(b.sessions[key], s)
}

// correlate refuses a second leg that does not belong to an attest-initiate that returned its Handle for its Target,
// Credential Type and kind.
func (b *Backend) correlate(kind string, handle []byte, target, credentialType, credentialHint string) error {
	return b.correlateKey(kind, hex.EncodeToString(handle), target, credentialType, credentialHint)
}

// correlateKey keeps the two legs of one exchange together, as the EST profile's processing says:
// a present-nonce request must repeat the Target of its attest-initiate, and a Credential Type or Credential Hint that
// attest-initiate named, while one it omitted may be named; a present-epoch Handle serves every request of the epoch
// for its Target, and the Credential Type and Hint are not correlated but forwarded to the RATS Relying Party.
func (b *Backend) correlateKey(kind, key, target, credentialType, credentialHint string) error {
	if kind != est.FreshnessPresentNonce && kind != est.FreshnessPresentEpoch {
		return nil // no Handle was returned; the RATS Relying Party checks the freshness element
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	now, live, match := time.Now(), 0, -1
	for i, s := range b.sessions[key] {
		if now.After(s.expires) {
			continue
		}
		live++
		if s.target != target || s.kind != kind {
			continue
		}
		if kind == est.FreshnessPresentNonce && ((s.credentialType != "" && s.credentialType != credentialType) ||
			(s.hint != "" && s.hint != credentialHint)) {
			continue
		}
		match = i
	}
	if live == 0 {
		return fail(http.StatusBadRequest, "no attest-initiate returned this Handle, or it expired")
	}
	if match < 0 {
		return fail(http.StatusBadRequest, "Target or Freshness Kind differ from the attest-initiate, or a Credential Type or Credential Hint it named is not repeated")
	}
	if kind == est.FreshnessPresentNonce { // single use
		ss := b.sessions[key]
		b.sessions[key] = append(ss[:match:match], ss[match+1:]...)
		if len(b.sessions[key]) == 0 {
			delete(b.sessions, key)
		}
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

// verifierFor picks, among the verifiers the RATS Relying Party takes, the one for the Evidence's TSM provider (N24: the RATS Relying Party's
// configuration chooses the verifier; the Evidence only picks among those, and there is no default for the rest).
func (b *Backend) verifierFor(relyingPartyName string, relyingParty RelyingParty, evidence []byte) (string, error) {
	var t struct {
		Provider string `cbor:"provider"`
	}
	provider := ""
	if cbor.Unmarshal(evidence, &t) == nil {
		provider = strings.TrimSpace(t.Provider)
	}
	for _, name := range relyingParty.Verifiers {
		if v := b.cfg.Verifiers[name]; v.Provider == provider {
			return name, nil
		}
	}
	return "", fail(http.StatusForbidden, "none of the verifiers RATS Relying Party %s takes appraises Evidence of provider %q", relyingPartyName, provider)
}

// verify obtains Attestation Results from the named verifier: a challenge-response session whose nonce is the
// binding value, computed with the RATS Relying Party's identifier, and the Evidence. It does not appraise the result; the RATS Relying Party does.
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

// The RATS models a RATS Relying Party may run in (RATS Relying Party.RATSModel).
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
	profile string, hintp *string, subject []byte) (string, RelyingParty, secondLeg, error) {
	name, relyingParty, err := b.route(target)
	if err != nil {
		return "", RelyingParty{}, secondLeg{}, err
	}
	if relyingParty.Mode != mode {
		// a request to the resource of the other mode: 400
		return "", RelyingParty{}, secondLeg{}, fail(http.StatusBadRequest, "the Target is provisioned by %s, not %s", relyingParty.Mode, mode)
	}
	// the Evidence format before the Handle: a request refused for its format (415) leaves the Handle to the next one,
	// as the profile's processing validates the media type before it correlates the Handle
	p, err := b.profile(profile)
	if err != nil {
		return "", RelyingParty{}, secondLeg{}, err
	}
	if err := b.correlate(kind, handle, target, credentialType, hint(hintp)); err != nil {
		return "", RelyingParty{}, secondLeg{}, err
	}
	leg := secondLeg{FreshnessKind: kind, Target: target, CredentialType: credentialType, CredentialHint: hint(hintp)}
	if relyingParty.RATSModel == backgroundCheck {
		// the RATS Relying Party asks the verifier, with the binding value it recomputes; this server does not
		leg.Evidence, leg.Profile = b64u(evidence), p
	} else {
		v, err := b.verifierFor(name, relyingParty, evidence)
		if err != nil {
			return "", RelyingParty{}, secondLeg{}, err
		}
		nonce := bindingValue(handle, target, subject)
		if leg.EAR, err = b.verify(ctx, v, evidence, p, nonce); err != nil {
			return "", RelyingParty{}, secondLeg{}, err
		}
		if relyingParty.ConduitAttack == conduitVerifier {
			// the drill: the Attestation Results go on under a signature of the conduit's own key, not the verifier's
			if leg.EAR, err = b.conduit.resign(leg.EAR); err != nil {
				return "", RelyingParty{}, secondLeg{}, fail(http.StatusInternalServerError, "conduit attack %s: %v", conduitVerifier, err)
			}
			b.conduit.logf(mode, target, "Attestation Results of verifier %s signed again with the conduit's own verifier key (SPKI SHA-256 %s)", v, b.conduit.spki)
		}
	}
	if len(handle) > 0 {
		leg.Handle = b64u(handle)
	}
	return name, relyingParty, leg, nil
}

// EnrollCredential forwards Evidence to a verifier the RATS Relying Party takes, then the CSR and Attestation Results to the
// Credential Authority;
// in Background Check, the CSR and the Evidence to the Credential Authority.
func (b *Backend) EnrollCredential(ctx context.Context, req *est.AttestedEnrollmentRequest, additionalPathSegment string, r *http.Request) (*x509.Certificate, error) {
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
		return nil, fail(http.StatusBadGateway, "RATS Relying Party %s returned no certificate", name)
	}
	der, err := base64.RawURLEncoding.DecodeString(out.CertificateChain[0])
	if err != nil {
		return nil, fail(http.StatusBadGateway, "RATS Relying Party %s: certificate is not base64url", name)
	}
	return x509.ParseCertificate(der)
}

// RetrieveCredential is not used: RetrieveCredentialRaw returns the Vault's container unchanged.
func (b *Backend) RetrieveCredential(context.Context, *est.AttestedRetrievalRequest, string, *http.Request) (*est.EncryptedCredentialBundle, error) {
	return nil, fail(http.StatusInternalServerError, "RetrieveCredentialRaw serves attest-retrieve")
}

// RetrieveCredentialRaw forwards Evidence to a verifier the RATS Relying Party takes, then CEKpub and the Attestation Results to the
// Secret Vault
// (in Background Check, CEKpub and the Evidence), and returns the Vault's encrypted container unchanged.
func (b *Backend) RetrieveCredentialRaw(ctx context.Context, req *est.AttestedRetrievalRequest, additionalPathSegment string, r *http.Request) ([]byte, error) {
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
