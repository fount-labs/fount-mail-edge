// Package deviceapi serves the Device API (design §8): the broker calls the edge
// over the attested tunnel, and every request is signed by the key that call's
// row requires. A signature covers the method, path, body hash, a timestamp, and
// a random nonce, so a captured request can't be replayed.
//
// This version implements the real signature discipline — canonicalisation,
// timestamp window, nonce replay cache, Ed25519 verification — and the full M2
// route table. Handlers are stubs that return 501 until their subsystems land
// (storage M2 step 4, pairing/recovery M2 step 6); the point of landing them now
// is that the signer requirement and the verification path are exercised and
// locked from the first commit (build order step 1: "finalize the device API").
//
// Canonical string signed by the caller (newline-separated):
//
//	<METHOD>\n<PATH>\n<hex sha256(body)>\n<unix-seconds timestamp>\n<nonce>
//
// Headers: Fount-Key-Id, Fount-Timestamp, Fount-Nonce, Fount-Signature (base64).
package deviceapi

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/fount-labs/fount-mail-edge/internal/entitlement"
	"github.com/fount-labs/fount-mail-edge/internal/limit"
	"github.com/fount-labs/fount-mail-edge/internal/routing"
	"github.com/fount-labs/fount-mail-edge/internal/store"
)

const (
	maxBodyBytes = 1 << 20 // 1 MiB; the Device API carries control messages, not mail
	// maxSendBodyBytes bounds POST /send, which carries a whole message base64 in
	// JSON: up to 10 MiB of message, room for a reply with its files attached.
	maxSendBodyBytes = 14 << 20
	timestampSkew    = 5 * time.Minute
	nonceRetention   = 10 * time.Minute
	maxNonceBytes    = 128
	maxNonces        = 1 << 18 // about 437 requests/sec sustained over the retention
	noncePruneGap    = time.Second
)

var (
	errNonceReplay = errors.New("nonce replay")
	errNonceFull   = errors.New("too many recent requests, retry later")
)

// signer names the key class a route's signature must come from (design §8).
type signer string

const (
	sigNone        signer = "none" // GET /boots/:id
	sigEntitlement signer = "entitlement"
	sigNewKeys     signer = "new-keys+entitlement"
	sigMailbox     signer = "mailbox"
	sigOwnerChange signer = "owner-change"
	sigAddress     signer = "address"
	sigPasskey     signer = "passkey"
	sigStripe      signer = "stripe-email-code"
)

// KeyResolver returns the Ed25519 public key registered under keyID for the given
// signer class, or ok=false. The source (mailbox record, routing list, passkey
// registration) lands with storage; until then it resolves nothing.
type KeyResolver interface {
	Resolve(class signer, keyID string) (ed25519.PublicKey, bool)
}

// KeyProvider supplies a mailbox's registered public keys, looked up by the hex
// mailbox id the broker sends as Fount-Key-Id (the M2 identity model, §4/§8).
// The routing layer implements it; deviceapi owns the mapping from signer class
// to key, so an implementer never names the unexported signer type. A false
// result makes guard answer 401 for that call.
type KeyProvider interface {
	AddressKey(keyID string) (ed25519.PublicKey, bool)     // request signing key (address-class routes)
	MailboxKey(keyID string) (ed25519.PublicKey, bool)     // POST /address
	OwnerChangeKey(keyID string) (ed25519.PublicKey, bool) // PUT /routing
}

// NewKeyResolver adapts a KeyProvider to the signer classes guard verifies
// against. The bootstrap classes (entitlement, new-keys, stripe) gate mailbox
// creation rather than an existing mailbox, so they are not resolvable from
// routing data in M2 and their routes stay 501; returning false here means such
// a call is refused at 401 before reaching the stub.
func NewKeyResolver(p KeyProvider) KeyResolver { return providerResolver{p} }

type providerResolver struct{ p KeyProvider }

func (r providerResolver) Resolve(class signer, keyID string) (ed25519.PublicKey, bool) {
	switch class {
	case sigAddress:
		return r.p.AddressKey(keyID)
	case sigMailbox:
		return r.p.MailboxKey(keyID)
	case sigOwnerChange:
		return r.p.OwnerChangeKey(keyID)
	default:
		// sigPasskey is deliberately absent: a passkey is an ES256 WebAuthn
		// credential, not an Ed25519 request signer, so POST /recover is
		// authenticated by a body assertion (internal/webauthn), not here.
		return nil, false
	}
}

type route struct {
	by    signer
	phase string
	desc  string
}

// m2routes is the authoritative Device API surface. Keep it in sync with design
// §8's table; adding a row here is how a call's signer requirement is locked.
var routes = map[string]route{
	"POST /mailbox":      {sigNewKeys, "M2", "Creates a mailbox and handle"},
	"GET /handle/{name}": {sigEntitlement, "M2", "Checks handle availability (rate limited)"},
	"POST /address":      {sigMailbox, "M2", "Adds an address + public key signed by the mailbox key"},
	"PUT /routing":       {sigOwnerChange, "M2", "Writes the versioned owner list"},
	"GET /mail":          {sigAddress, "M2", "Lists waiting messages"},
	"GET /mail/{id}":     {sigAddress, "M2", "Returns a message and its signature"},
	"DELETE /mail/{id}":  {sigAddress, "M2", "Confirms receipt and deletes"},
	"GET /gaps":          {sigAddress, "M2", "Lists signed records for sequence numbers with no message"},
	"GET /boots/{id}":    {sigNone, "M2", "Returns a boot's attestation"},
	"GET /recover/{id}":  {sigNone, "M2", "Issues a recovery challenge bound to a mailbox and new keys (§5)"},
	"POST /recover":      {sigPasskey, "M2", "Accepts a new mailbox key after a lost device (§5)"},
	"POST /entitlement":  {sigAddress, "M2", "Renews the mailbox's entitlement"},
	"POST /pause":        {sigPasskey, "M3", "Pauses or resumes a worker from another device"},
	"POST /send":         {sigAddress, "M3", "Sends to owners"},
	"POST /connect":      {sigOwnerChange, "M3", "Mails a would-be owner from the worker; their reply proves them on PUT /routing"},
	"POST /reset":        {sigStripe, "M3", "Starts a new mailbox on the same handle"},
	"GET /pause/{id}":    {sigNone, "M3", "Issues a pause challenge bound to a worker and a state (§12)"},
}

// builtM3 are the M3 routes that are built, so the shim forwards them.
var builtM3 = map[string]bool{
	"GET /pause/{id}": true,
	"POST /pause":     true,
	"POST /send":      true,
	"POST /connect":   true,
}

// Route is one row of the route table, for callers that mount or expose the API.
type Route struct {
	Pattern string // a net/http ServeMux pattern, e.g. "GET /mail/{id}"
	Phase   string // the milestone the route belongs to, e.g. "M2"
	Public  bool   // built, so tinfoil-config.yml's shim forwards it
}

// Routes lists the route table, sorted by pattern.
func Routes() []Route {
	out := make([]Route, 0, len(routes))
	for p, r := range routes {
		out = append(out, Route{Pattern: p, Phase: r.phase, Public: r.phase == "M2" || builtM3[p]})
	}
	slices.SortFunc(out, func(a, b Route) int { return strings.Compare(a.Pattern, b.Pattern) })
	return out
}

// Provisioner creates mailboxes and checks handle availability (design §8
// POST /mailbox, GET /handle). routing.Store implements it; nil leaves those
// routes as 501 stubs.
type Provisioner interface {
	Available(ctx context.Context, address string) (bool, error)
	Create(ctx context.Context, p routing.NewMailbox) (mailboxID []byte, err error)
}

// Mutator is the per-mailbox routing layer behind the signed write routes
// (design §8 POST /address, PUT /routing, POST /entitlement, POST /recover).
// RotateKeys and PasskeyOf back recovery: the latter reads the registered
// passkey credential key the assertion is verified against. LicenseOf keys the
// per-license limits. routing.Store implements it; nil leaves those routes as 501
// stubs.
type Mutator interface {
	AddAddress(ctx context.Context, p routing.NewAddress) (mailboxID []byte, err error)
	SetOwners(ctx context.Context, mailboxID []byte, version uint64, owners []string, proofs ...routing.ConnectProof) error
	RenewEntitlement(ctx context.Context, mailboxID, licenseHash []byte, exp int64) error
	RotateKeys(ctx context.Context, mailboxID []byte, k routing.RotatedKeys) (newMailboxKeyHash []byte, err error)
	PasskeyOf(mailboxID []byte) (credPubKey []byte, ok bool)
	LicenseOf(mailboxID []byte) (licenseHash []byte, ok bool)
}

// Options configures the API. Store is required; the rest enable the routes that
// depend on them (nil leaves those routes 501/401).
type Options struct {
	Store       store.Store
	Resolver    KeyResolver       // per-mailbox signer keys (address/mailbox/owner-change/passkey)
	Entitlement ed25519.PublicKey // verifies device entitlements; nil disables entitlement routes
	Provisioner Provisioner       // mailbox creation + handle checks
	Mutator     Mutator           // per-mailbox routing writes (address/routing/entitlement/recover)
	MailDomain  string            // e.g. "@fountbox.com"; a handle's address is name+domain

	// RecoveryRPID is the WebAuthn Relying Party id (the Fount domain serving
	// the passkey's associated-domain file) that POST /recover verifies passkey
	// assertions against; POST /pause uses it too. Empty leaves recovery and
	// pause as 501 stubs. RecoveryOrigin, when set, additionally pins the
	// assertion's clientDataJSON origin.
	RecoveryRPID   string
	RecoveryOrigin string

	// Sender backs POST /send (M3). nil leaves it 501.
	Sender Sender

	// Connector backs POST /connect. nil, sending off, answers 503.
	Connector Connector

	// HandleLimiter throttles every route that shows whether an address is taken
	// (§8), keyed by the caller's license so one subscription can't enumerate the
	// namespace. nil builds a per-enclave default.
	HandleLimiter *limit.Limiter
}

type API struct {
	mux           *http.ServeMux
	store         store.Store
	resolver      KeyResolver
	entVerify     ed25519.PublicKey
	provisioner   Provisioner
	mutator       Mutator
	mailDomain    string
	recoverRPID   string
	recoverOrigin string
	recoverKey    []byte // per-boot HMAC key for stateless recovery challenges
	keylog        store.KeyLog
	gaps          store.GapReader
	pauser        Pauser // from the Mutator; nil leaves POST /pause 501
	nonces        *nonceCache
	handleLimiter *limit.Limiter
	sender        Sender
	connector     Connector
}

func New(o Options) *API {
	a := &API{
		mux:           http.NewServeMux(),
		store:         o.Store,
		resolver:      o.Resolver,
		entVerify:     o.Entitlement,
		provisioner:   o.Provisioner,
		mutator:       o.Mutator,
		mailDomain:    o.MailDomain,
		recoverRPID:   o.RecoveryRPID,
		recoverOrigin: o.RecoveryOrigin,
		recoverKey:    make([]byte, 32),
		nonces:        newNonceCache(),
		handleLimiter: o.HandleLimiter,
		sender:        o.Sender,
		connector:     o.Connector,
	}
	if a.handleLimiter == nil {
		a.handleLimiter = limit.New(5, 30) // 5 checks/sec, burst 30, per license
	}
	if _, err := rand.Read(a.recoverKey); err != nil {
		panic("deviceapi: cannot read random for recovery challenge key: " + err.Error())
	}
	mail, _ := o.Store.(store.MailReader) // nil in dev (discard store) -> routes stay 501
	boots, _ := o.Store.(store.BootStore) // same
	a.keylog, _ = o.Store.(store.KeyLog)  // same; nil leaves POST /recover 501
	a.gaps, _ = o.Store.(store.GapReader) // same
	a.pauser, _ = o.Mutator.(Pauser)
	for pattern, r := range routes {
		a.mux.Handle(pattern, a.guard(r, bodyLimit(pattern), a.handler(pattern, r, mail, boots)))
	}
	return a
}

// handler returns the real handler for a route, or the 501 stub for routes whose
// subsystem isn't live yet. Read routes need a MailReader store; creation needs a
// Provisioner; the per-mailbox write routes need a Mutator; GET /boots needs a
// BootStore.
func (a *API) handler(pattern string, rt route, mail store.MailReader, boots store.BootStore) http.Handler {
	switch {
	case mail != nil && pattern == "GET /mail":
		return a.listMail(mail)
	case mail != nil && pattern == "GET /mail/{id}":
		return a.getMail(mail)
	case mail != nil && pattern == "DELETE /mail/{id}":
		return a.deleteMail(mail)
	case a.gaps != nil && pattern == "GET /gaps":
		return a.listGaps()
	case a.provisioner != nil && pattern == "POST /mailbox":
		return a.createMailbox()
	case a.provisioner != nil && pattern == "GET /handle/{name}":
		return a.checkHandle()
	case a.mutator != nil && pattern == "POST /address":
		return a.createAddress()
	case a.mutator != nil && pattern == "PUT /routing":
		return a.putRouting()
	case a.mutator != nil && pattern == "POST /entitlement":
		return a.renewEntitlement()
	case boots != nil && pattern == "GET /boots/{id}":
		return a.getBoot(boots)
	case a.recoveryLive() && pattern == "GET /recover/{id}":
		return a.issueRecoveryChallenge()
	case a.recoveryLive() && pattern == "POST /recover":
		return a.recover()
	case a.sender != nil && pattern == "POST /send":
		return a.sendMail()
	case pattern == "POST /connect":
		return a.connect()
	}
	if h := a.ownerControl(pattern); h != nil {
		return h
	}
	return a.stub(pattern, rt)
}

// recoveryLive reports whether POST /recover and its challenge endpoint can run:
// a Relying Party id to verify assertions against, a Mutator to rotate keys, and
// the write-once key log to record the new key in. Missing any leaves recovery a
// 501 stub, so an edge can never rotate a mailbox key without logging it (§9).
func (a *API) recoveryLive() bool {
	return a.recoverRPID != "" && a.mutator != nil && a.keylog != nil
}

func (a *API) ServeHTTP(w http.ResponseWriter, r *http.Request) { a.mux.ServeHTTP(w, r) }

// guard authorizes a request for the route's signer class, then runs next. For
// per-mailbox classes the signing key comes from routing data (Fount-Key-Id);
// for the entitlement-bearing classes it comes from a signed entitlement token,
// whose claims are attached to the request context for the handler.
// bodyLimit is the most a route's request body may hold.
func bodyLimit(pattern string) int {
	if pattern == "POST /send" {
		return maxSendBodyBytes
	}
	return maxBodyBytes
}

func (a *API) guard(rt route, limit int, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(io.LimitReader(r.Body, int64(limit)+1))
		if err != nil || len(body) > limit {
			writeErr(w, http.StatusRequestEntityTooLarge, "body too large")
			return
		}
		r.Body = io.NopCloser(bytes.NewReader(body))

		if rt.by == sigNone {
			next.ServeHTTP(w, r)
			return
		}
		ctx, err := a.authorize(rt.by, r, body)
		if err != nil {
			writeErr(w, nonceStatus(err), err.Error())
			return
		}
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

type claimsCtxKey struct{}

func claimsFrom(ctx context.Context) (*entitlement.Claims, bool) {
	c, ok := ctx.Value(claimsCtxKey{}).(*entitlement.Claims)
	return c, ok
}

// nonceStatus is the HTTP status for an authorization or nonce error. A full cache
// isn't the caller's fault, so it asks for a retry instead of reporting a bad
// signature.
func nonceStatus(err error) int {
	if errors.Is(err, errNonceFull) {
		return http.StatusServiceUnavailable
	}
	return http.StatusUnauthorized
}

// authorize checks the timestamp window, the request signature, and the nonce. It
// returns the context to run the handler under (carrying entitlement claims for
// the entitlement classes), or an error for nonceStatus.
//
// The nonce is recorded last, so only a request that proved its signature can add
// to the cache. POST /recover has no signature here, so its handler records the
// nonce after the passkey assertion verifies.
func (a *API) authorize(class signer, r *http.Request, body []byte) (context.Context, error) {
	tsRaw := r.Header.Get("Fount-Timestamp")
	nonce := r.Header.Get("Fount-Nonce")
	if tsRaw == "" || nonce == "" {
		return nil, fmt.Errorf("missing signature headers")
	}
	if len(nonce) > maxNonceBytes {
		return nil, fmt.Errorf("nonce too long")
	}
	ts, err := strconv.ParseInt(tsRaw, 10, 64)
	if err != nil {
		return nil, fmt.Errorf("bad timestamp")
	}
	if d := time.Since(time.Unix(ts, 0)); d > timestampSkew || d < -timestampSkew {
		return nil, fmt.Errorf("timestamp outside window")
	}

	// A lost device has no request-signing key, so POST /recover carries no
	// Fount-Signature; the handler authenticates it by the passkey assertion in
	// the body (§5).
	if class == sigPasskey {
		return r.Context(), nil
	}

	ctx, err := a.verifySignature(class, r, body, ts, nonce)
	if err != nil {
		return nil, err
	}
	if err := a.nonces.useOnce(nonce, time.Unix(ts, 0)); err != nil {
		return nil, err
	}
	return ctx, nil
}

// verifySignature checks the request's signature against the key its class names.
func (a *API) verifySignature(class signer, r *http.Request, body []byte, ts int64, nonce string) (context.Context, error) {
	sigB64 := r.Header.Get("Fount-Signature")
	if sigB64 == "" {
		return nil, fmt.Errorf("missing signature headers")
	}
	sig, err := base64.StdEncoding.DecodeString(sigB64)
	if err != nil {
		return nil, fmt.Errorf("bad signature encoding")
	}
	canonical := []byte(canonicalString(r.Method, r.URL.Path, body, ts, nonce))

	if class == sigEntitlement || class == sigNewKeys {
		claims, err := a.verifyEntitlement(r, canonical, sig)
		if err != nil {
			return nil, err
		}
		return context.WithValue(r.Context(), claimsCtxKey{}, claims), nil
	}

	keyID := r.Header.Get("Fount-Key-Id")
	if keyID == "" {
		return nil, fmt.Errorf("missing key id")
	}
	if a.resolver == nil {
		return nil, fmt.Errorf("no key registered for %s (storage not yet live)", class)
	}
	pub, ok := a.resolver.Resolve(class, keyID)
	if !ok {
		return nil, fmt.Errorf("unknown %s key", class)
	}
	if !ed25519.Verify(pub, canonical, sig) {
		return nil, fmt.Errorf("signature does not verify")
	}
	return r.Context(), nil
}

// verifyEntitlement checks the presented entitlement token and that the request
// was signed by the device key the token names (so a leaked token can't be
// replayed with another key).
func (a *API) verifyEntitlement(r *http.Request, canonical, sig []byte) (*entitlement.Claims, error) {
	if len(a.entVerify) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("entitlement verification not configured")
	}
	tok := r.Header.Get("Fount-Entitlement")
	if tok == "" {
		return nil, fmt.Errorf("missing entitlement")
	}
	claims, err := entitlement.Verify(tok, a.entVerify, time.Now(), timestampSkew)
	if err != nil {
		return nil, err
	}
	if !ed25519.Verify(claims.DeviceKey, canonical, sig) {
		return nil, fmt.Errorf("request not signed by the entitled device key")
	}
	return claims, nil
}

func canonicalString(method, path string, body []byte, ts int64, nonce string) string {
	sum := sha256.Sum256(body)
	return fmt.Sprintf("%s\n%s\n%s\n%d\n%s", method, path, hex.EncodeToString(sum[:]), ts, nonce)
}

func (a *API) stub(pattern string, rt route) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusNotImplemented)
		_ = json.NewEncoder(w).Encode(map[string]string{
			"error":     "not implemented",
			"route":     pattern,
			"phase":     rt.phase,
			"signed_by": string(rt.by),
			"note":      rt.desc,
		})
	})
}

// allowProbe spends from the license's shared budget for routes that show whether
// an address is taken, answering 429 if it's empty.
func (a *API) allowProbe(w http.ResponseWriter, license []byte) bool {
	if a.handleLimiter.Allow(hex.EncodeToString(license)) {
		return true
	}
	w.Header().Set("Retry-After", "1")
	writeErr(w, http.StatusTooManyRequests, "too many handle checks, slow down")
	return false
}

// logKey is the routing write paths' hook into the write-once key log, or nil where
// the store has none.
func (a *API) logKey() routing.LogKey {
	if a.keylog == nil {
		return nil
	}
	return func(ctx context.Context, mailboxID, keyHash []byte) error {
		return a.keylog.AppendMailboxKeyHash(ctx, hex.EncodeToString(mailboxID), keyHash, time.Now().Unix())
	}
}

// writeFailure answers a failed routing write: 503 if another edge got there first,
// because the same request will work on a retry, and otherwise 500 with msg.
func writeFailure(w http.ResponseWriter, err error, msg string) {
	if errors.Is(err, store.ErrConflict) {
		w.Header().Set("Retry-After", "1")
		writeErr(w, http.StatusServiceUnavailable, "write conflict, retry")
		return
	}
	writeErr(w, http.StatusInternalServerError, msg)
}

func writeErr(w http.ResponseWriter, code int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": msg})
}

// --- nonce replay cache ----------------------------------------------------

type nonceCache struct {
	mu     sync.Mutex
	seen   map[string]time.Time
	max    int
	pruned time.Time
}

func newNonceCache() *nonceCache {
	return &nonceCache{seen: make(map[string]time.Time), max: maxNonces}
}

// useOnce records a nonce. It returns errNonceReplay if the nonce was used within
// the retention window, and errNonceFull if the cache is at its cap, because
// dropping an entry to make room would let that nonce replay. Tied to the request
// timestamp so the window is bounded.
func (c *nonceCache) useOnce(nonce string, ts time.Time) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	now := time.Now()
	if now.Sub(c.pruned) >= noncePruneGap {
		c.pruned = now
		for k, t := range c.seen {
			if now.Sub(t) > nonceRetention {
				delete(c.seen, k)
			}
		}
	}
	if _, ok := c.seen[nonce]; ok {
		return errNonceReplay
	}
	if len(c.seen) >= c.max {
		return errNonceFull
	}
	c.seen[nonce] = ts
	return nil
}
