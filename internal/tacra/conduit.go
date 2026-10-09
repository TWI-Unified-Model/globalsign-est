package tacra

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/globalsign/est"
)

// The conduit's drills (RRP.ConduitAttack): what this server does, as TACRA's untrusted conduit, against an RRP in a
// drill of the bench. Each act is one line of the conduit log, "conduit attack NAME: Enrollment|Retrieval for
// TARGET: …", which the bench's verdict reads.
const conduitVerifier = "verifier"

// conduit is the attacking conduit of a drill: a verifier key of its own, and the log of what it did.
type conduit struct {
	key  *ecdsa.PrivateKey // the conduit's own verifier key: one no RRP was provisioned with
	spki string            // SHA-256 of its SubjectPublicKeyInfo, hex, for the record
	mu   sync.Mutex
	log  io.Writer
}

func newConduit(logPath string) (*conduit, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	der, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		return nil, err
	}
	sum := sha256.Sum256(der)
	c := &conduit{key: key, spki: hex.EncodeToString(sum[:]), log: os.Stderr}
	if logPath != "" {
		f, err := os.OpenFile(logPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
		if err != nil {
			return nil, fmt.Errorf("conduit log: %w", err)
		}
		c.log = f
	}
	c.line("conduit attack %s, this server's own verifier key: SPKI SHA-256 %s", conduitVerifier, c.spki)
	return c, nil
}

// logf records one act against the request of mode (enroll or retrieve) for the Target.
func (c *conduit) logf(mode, target, format string, v ...any) {
	what := "Retrieval"
	if mode == est.MechanismEnroll {
		what = "Enrollment"
	}
	c.line("conduit attack %s: %s for %s: %s", conduitVerifier, what, target, fmt.Sprintf(format, v...))
}

func (c *conduit) line(format string, v ...any) {
	c.mu.Lock()
	defer c.mu.Unlock()
	fmt.Fprintf(c.log, "%s %s\n", time.Now().UTC().Format(time.RFC3339), fmt.Sprintf(format, v...))
}

// resign returns the compact JWS with its header and payload as they are, and in place of the verifier's signature one
// of this conduit's own key (ES256: r and s, 32 octets each), as a Verifier of the conduit's own would have signed
// the same Attestation Results.
func (c *conduit) resign(jws string) (string, error) {
	parts := strings.Split(jws, ".")
	if len(parts) != 3 {
		return "", errors.New("the Attestation Results are not a compact JWS")
	}
	digest := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	r, s, err := ecdsa.Sign(rand.Reader, c.key, digest[:])
	if err != nil {
		return "", err
	}
	sig := make([]byte, 64)
	r.FillBytes(sig[:32])
	s.FillBytes(sig[32:])
	return parts[0] + "." + parts[1] + "." + base64.RawURLEncoding.EncodeToString(sig), nil
}
