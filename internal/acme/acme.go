// Package acme is a minimal RFC 8555 (ACME v2) client, HTTP-01 only, built for
// one job: get a CA certificate for the enclave's attested TLS key each boot
// (design §6).
//
// Two keys, deliberately distinct:
//
//   - The ACME *account* key comes from the vault keyset (ACME_ACCOUNT_KEY), which
//     KEYSET_COMMITMENT pins, so the account and its URL are the same every boot.
//     CAA pins the account with `accounturi`, so a taken-over gateway can't get a
//     certificate for the mail hostname on its own. AccountURL publishes the URL.
//   - The *certificate* key is the per-boot attested `mail-tls` key. Its public
//     half is in the attestation, so the issued cert provably binds the enclave.
//
// The HTTP-01 challenge is served on the ACME port, which the gateway forwards
// from public port 80. This is a direct port of the flow proven live on
// 2026-11-05 (a production cert issued for an attested key over HTTP-01 through
// the gateway, no DNS credential — see ~/Desktop/code/tinfoil-port25-test), now
// in Go and dependency-free.
//
// Each boot adds one random name under BOOT_HOSTNAME_DOMAIN to its certificate
// (bootname.go), so Let's Encrypt's 5 a week for the same set of names never
// applies. TODO(§6): a second CA as backup, for when Let's Encrypt refuses.
package acme

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// Challenges holds pending HTTP-01 key authorizations and answers the gateway's
// challenge requests. It is shared between the Issuer (which sets tokens) and the
// responder HTTP server (which serves them).
type Challenges struct {
	store    sync.Map // token -> keyAuthorization
	firstHit chan struct{}
	once     sync.Once
}

func NewChallenges() *Challenges {
	return &Challenges{firstHit: make(chan struct{})}
}

// Reachable closes the first time the challenge responder is hit, which is the
// signal that the gateway's tunnel to the edge is live (design §6: issue only
// after the gateway's first health check).
func (c *Challenges) Reachable() <-chan struct{} { return c.firstHit }

func (c *Challenges) set(token, keyAuth string) { c.store.Store(token, keyAuth) }
func (c *Challenges) clear(token string)        { c.store.Delete(token) }

// Handler serves /.well-known/acme-challenge/<token> and answers 200 on anything
// else (so HAProxy's health check passes). Any request signals reachability.
func (c *Challenges) Handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c.once.Do(func() { close(c.firstHit) })
		if token, ok := strings.CutPrefix(r.URL.Path, "/.well-known/acme-challenge/"); ok {
			if v, ok := c.store.Load(token); ok {
				_, _ = io.WriteString(w, v.(string))
				return
			}
			http.NotFound(w, r)
			return
		}
		_, _ = io.WriteString(w, "ok\n")
	})
}

// Issuer is safe for concurrent use: Register and Issue take turns.
type Issuer struct {
	mu         sync.Mutex // one ACME conversation at a time: the nonce and kid are shared
	accountURL atomic.Pointer[string]

	directory  string
	account    *ecdsa.PrivateKey
	jwk        map[string]string
	thumbprint string
	challenges *Challenges
	http       *http.Client

	dir   directoryURLs
	kid   string
	nonce string
}

// NewIssuer builds an Issuer from the PEM account key delivered by the keyserver.
func NewIssuer(accountKeyPEM []byte, directory string, ch *Challenges) (*Issuer, error) {
	key, err := parseECKey(accountKeyPEM)
	if err != nil {
		return nil, fmt.Errorf("acme account key: %w", err)
	}
	jwk := map[string]string{
		"crv": "P-256",
		"kty": "EC",
		"x":   b64(key.X.FillBytes(make([]byte, 32))),
		"y":   b64(key.Y.FillBytes(make([]byte, 32))),
	}
	// JWK thumbprint over the required members in lexicographic order (RFC 7638).
	canonical := fmt.Sprintf(`{"crv":"%s","kty":"%s","x":"%s","y":"%s"}`, jwk["crv"], jwk["kty"], jwk["x"], jwk["y"])
	sum := sha256.Sum256([]byte(canonical))
	return &Issuer{
		directory:  directory,
		account:    key,
		jwk:        jwk,
		thumbprint: b64(sum[:]),
		challenges: ch,
		http:       &http.Client{Timeout: 30 * time.Second},
	}, nil
}

// Issue runs one order covering every hostname and returns a tls.Certificate
// backed by certKey (the attested mail-tls key). Each name is validated, so every
// gateway must be up for the order to pass.
func (i *Issuer) Issue(ctx context.Context, hostnames []string, certKey *ecdsa.PrivateKey) (*tls.Certificate, error) {
	csr, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		DNSNames: hostnames,
	}, certKey)
	if err != nil {
		return nil, fmt.Errorf("csr: %w", err)
	}
	chainPEM, err := i.IssueCSR(ctx, hostnames, csr)
	if err != nil {
		return nil, err
	}
	return buildCert(chainPEM, certKey)
}

// IssueCSR is Issue for a CSR signed elsewhere: in a split edge, mail-front holds
// the mail-tls key and makes the CSR, and mail-core, which holds the account key,
// runs the order. It returns the PEM chain, with no private key.
func (i *Issuer) IssueCSR(ctx context.Context, hostnames []string, csr []byte) ([]byte, error) {
	i.mu.Lock()
	defer i.mu.Unlock()
	if err := i.loadDirectory(ctx); err != nil {
		return nil, err
	}
	if err := i.register(ctx); err != nil {
		return nil, fmt.Errorf("newAccount: %w", err)
	}

	identifiers := make([]map[string]string, len(hostnames))
	for n, h := range hostnames {
		identifiers[n] = map[string]string{"type": "dns", "value": h}
	}
	orderHdr, orderBody, err := i.post(ctx, i.dir.NewOrder, map[string]any{"identifiers": identifiers})
	if err != nil {
		return nil, fmt.Errorf("newOrder: %w", err)
	}
	orderURL := orderHdr.Get("Location")
	var order struct {
		Authorizations []string `json:"authorizations"`
		Finalize       string   `json:"finalize"`
	}
	if err := json.Unmarshal(orderBody, &order); err != nil {
		return nil, err
	}

	for _, authzURL := range order.Authorizations {
		if err := i.solveHTTP01(ctx, authzURL); err != nil {
			return nil, err
		}
	}

	if _, _, err := i.post(ctx, order.Finalize, map[string]any{"csr": b64(csr)}); err != nil {
		return nil, fmt.Errorf("finalize: %w", err)
	}

	finalOrder, err := i.waitValid(ctx, orderURL)
	if err != nil {
		return nil, fmt.Errorf("order: %w", err)
	}
	var fo struct {
		Certificate string `json:"certificate"`
	}
	if err := json.Unmarshal(finalOrder, &fo); err != nil {
		return nil, err
	}
	_, chainPEM, err := i.post(ctx, fo.Certificate, nil) // POST-as-GET
	if err != nil {
		return nil, fmt.Errorf("download cert: %w", err)
	}
	return chainPEM, nil
}

// Register finds or creates the account without ordering a certificate, so the
// account URL is known on a boot that reloads a cached certificate, and before the
// first issuance (CAA can then pin it before the edge ever orders).
func (i *Issuer) Register(ctx context.Context) error {
	i.mu.Lock()
	defer i.mu.Unlock()
	if err := i.loadDirectory(ctx); err != nil {
		return fmt.Errorf("directory: %w", err)
	}
	if err := i.register(ctx); err != nil {
		return fmt.Errorf("newAccount: %w", err)
	}
	return nil
}

// AccountURL is the CA's URL for this account (the `kid`), which CAA `accounturi`
// pins. It's public, and "" until a newAccount call has answered.
func (i *Issuer) AccountURL() string {
	if u := i.accountURL.Load(); u != nil {
		return *u
	}
	return ""
}

func (i *Issuer) solveHTTP01(ctx context.Context, authzURL string) error {
	_, body, err := i.post(ctx, authzURL, nil)
	if err != nil {
		return fmt.Errorf("authz: %w", err)
	}
	var authz struct {
		Challenges []struct {
			Type, URL, Token string
		} `json:"challenges"`
	}
	if err := json.Unmarshal(body, &authz); err != nil {
		return err
	}
	var token, url string
	for _, c := range authz.Challenges {
		if c.Type == "http-01" {
			token, url = c.Token, c.URL
		}
	}
	if token == "" {
		return fmt.Errorf("no http-01 challenge offered")
	}
	i.challenges.set(token, token+"."+i.thumbprint)
	defer i.challenges.clear(token)

	if _, _, err := i.post(ctx, url, map[string]any{}); err != nil { // tell the CA to validate
		return fmt.Errorf("challenge: %w", err)
	}
	if _, err := i.waitValid(ctx, authzURL); err != nil {
		return fmt.Errorf("authz validation: %w", err)
	}
	return nil
}

// --- ACME plumbing ---------------------------------------------------------

func (i *Issuer) loadDirectory(ctx context.Context) error {
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, i.directory, nil)
	res, err := i.http.Do(req)
	if err != nil {
		return err
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		return fmt.Errorf("directory answered %s", res.Status)
	}
	var d directoryURLs
	if err := json.NewDecoder(res.Body).Decode(&d); err != nil {
		return err
	}
	if d.NewNonce == "" || d.NewAccount == "" {
		return fmt.Errorf("directory lacks newNonce or newAccount")
	}
	i.dir = d
	return nil
}

// directoryURLs holds the directory entries the issuer uses. A real directory also
// has a "meta" object and random keys (RFC 8555 §7.1.1), which are ignored.
type directoryURLs struct {
	NewNonce   string `json:"newNonce"`
	NewAccount string `json:"newAccount"`
	NewOrder   string `json:"newOrder"`
}

// register finds or creates the account. It can run again after a failed Issue,
// and newAccount must always be signed with the jwk (RFC 8555 §6.2), so it clears
// any kid left by the earlier attempt.
func (i *Issuer) register(ctx context.Context) error {
	i.kid = ""
	hdr, _, err := i.post(ctx, i.dir.NewAccount, map[string]any{"termsOfServiceAgreed": true})
	if err != nil {
		return err
	}
	i.kid = hdr.Get("Location")
	if i.kid == "" {
		return fmt.Errorf("newAccount answered with no Location")
	}
	url := i.kid
	i.accountURL.Store(&url)
	return nil
}

func (i *Issuer) freshNonce(ctx context.Context) (string, error) {
	req, _ := http.NewRequestWithContext(ctx, http.MethodHead, i.dir.NewNonce, nil)
	res, err := i.http.Do(req)
	if err != nil {
		return "", err
	}
	defer res.Body.Close()
	return res.Header.Get("Replay-Nonce"), nil
}

// post sends a signed JWS. payload==nil means POST-as-GET (empty payload).
func (i *Issuer) post(ctx context.Context, url string, payload any) (http.Header, []byte, error) {
	var lastErr error
	for attempt := 0; attempt < 3; attempt++ {
		if i.nonce == "" {
			n, err := i.freshNonce(ctx)
			if err != nil {
				return nil, nil, err
			}
			i.nonce = n
		}
		protected := map[string]any{"alg": "ES256", "nonce": i.nonce, "url": url}
		if i.kid != "" {
			protected["kid"] = i.kid
		} else {
			protected["jwk"] = i.jwk
		}
		i.nonce = ""

		protB, _ := json.Marshal(protected)
		prot64 := b64(protB)
		var pay64 string
		if payload != nil {
			payB, _ := json.Marshal(payload)
			pay64 = b64(payB)
		}
		sig, err := i.sign(prot64 + "." + pay64)
		if err != nil {
			return nil, nil, err
		}
		jws, _ := json.Marshal(map[string]string{"protected": prot64, "payload": pay64, "signature": sig})

		req, _ := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(jws))
		req.Header.Set("Content-Type", "application/jose+json")
		res, err := i.http.Do(req)
		if err != nil {
			return nil, nil, err
		}
		body, _ := io.ReadAll(res.Body)
		res.Body.Close()
		if n := res.Header.Get("Replay-Nonce"); n != "" {
			i.nonce = n
		}
		if res.StatusCode >= 400 {
			if bytes.Contains(body, []byte("badNonce")) {
				lastErr = fmt.Errorf("badNonce, retrying")
				continue
			}
			err := fmt.Errorf("%s: %d %s", url, res.StatusCode, truncate(body))
			if d := parseRetryAfter(res.Header.Get("Retry-After"), time.Now()); d > 0 {
				return nil, nil, &retryAfterError{err, d}
			}
			return nil, nil, err
		}
		return res.Header, body, nil
	}
	return nil, nil, fmt.Errorf("%s: %v", url, lastErr)
}

// retryAfterError is a refusal the CA attached a wait to. The certificate loop finds
// it through its RetryAfter method.
type retryAfterError struct {
	err   error
	after time.Duration
}

func (e *retryAfterError) Error() string             { return e.err.Error() }
func (e *retryAfterError) Unwrap() error             { return e.err }
func (e *retryAfterError) RetryAfter() time.Duration { return e.after }

// parseRetryAfter reads either form of the header: seconds, or an HTTP date.
func parseRetryAfter(v string, now time.Time) time.Duration {
	if v == "" {
		return 0
	}
	if secs, err := strconv.Atoi(v); err == nil {
		return time.Duration(secs) * time.Second
	}
	if at, err := http.ParseTime(v); err == nil {
		return at.Sub(now)
	}
	return 0
}

func (i *Issuer) waitValid(ctx context.Context, url string) ([]byte, error) {
	for n := 0; n < 60; n++ {
		_, body, err := i.post(ctx, url, nil)
		if err != nil {
			return nil, err
		}
		var s struct {
			Status string `json:"status"`
		}
		_ = json.Unmarshal(body, &s)
		switch s.Status {
		case "valid":
			return body, nil
		case "invalid":
			return nil, fmt.Errorf("status invalid: %s", truncate(body))
		}
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(time.Second):
		}
	}
	return nil, fmt.Errorf("timed out waiting for %s", url)
}

// sign produces an ES256 JWS signature (raw R||S, 64 bytes, base64url).
func (i *Issuer) sign(signingInput string) (string, error) {
	h := sha256.Sum256([]byte(signingInput))
	r, s, err := ecdsa.Sign(rand.Reader, i.account, h[:])
	if err != nil {
		return "", err
	}
	out := make([]byte, 64)
	r.FillBytes(out[:32])
	s.FillBytes(out[32:])
	return b64(out), nil
}

// --- helpers ---------------------------------------------------------------

func b64(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

func parseECKey(pemBytes []byte) (*ecdsa.PrivateKey, error) {
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return nil, fmt.Errorf("no PEM block")
	}
	if k, err := x509.ParseECPrivateKey(block.Bytes); err == nil {
		return k, nil
	}
	anyKey, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	k, ok := anyKey.(*ecdsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("not an ECDSA key (%T)", anyKey)
	}
	return k, nil
}

func buildCert(chainPEM []byte, key *ecdsa.PrivateKey) (*tls.Certificate, error) {
	var der [][]byte
	rest := chainPEM
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		if block.Type == "CERTIFICATE" {
			der = append(der, block.Bytes)
		}
	}
	if len(der) == 0 {
		return nil, fmt.Errorf("no certificate in chain")
	}
	return &tls.Certificate{Certificate: der, PrivateKey: key}, nil
}

func truncate(b []byte) string {
	const n = 400
	if len(b) > n {
		return string(b[:n])
	}
	return string(b)
}
