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
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"sync"
	"time"

	"github.com/fount-labs/fount-mail-edge/internal/store"
)

const (
	maxBodyBytes   = 1 << 20 // 1 MiB; the Device API carries control messages, not mail
	timestampSkew  = 5 * time.Minute
	nonceRetention = 10 * time.Minute
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
	"GET /boots/{id}":    {sigNone, "M2", "Returns a boot's attestation"},
	"POST /recover":      {sigPasskey, "M2", "Accepts a new mailbox key after a lost device (§5)"},
	"POST /entitlement":  {sigAddress, "M2", "Renews the mailbox's entitlement"},
	"POST /pause":        {sigPasskey, "M3", "Pauses or resumes a worker from another device"},
	"POST /send":         {sigAddress, "M3", "Sends to owners"},
	"POST /reset":        {sigStripe, "M3", "Starts a new mailbox on the same handle"},
}

type API struct {
	mux      *http.ServeMux
	store    store.Store
	resolver KeyResolver
	nonces   *nonceCache
}

func New(st store.Store, resolver KeyResolver) *API {
	a := &API{
		mux:      http.NewServeMux(),
		store:    st,
		resolver: resolver,
		nonces:   newNonceCache(),
	}
	mail, _ := st.(store.MailReader) // nil in dev (discard store) -> routes stay 501
	for pattern, r := range routes {
		a.mux.Handle(pattern, a.guard(r, a.handler(pattern, r, mail)))
	}
	return a
}

// handler returns the real handler for a route, or the 501 stub for routes
// whose subsystem isn't live yet. The mail read routes (GET/DELETE /mail) are
// live once the store is a MailReader.
func (a *API) handler(pattern string, rt route, mail store.MailReader) http.Handler {
	if mail != nil {
		switch pattern {
		case "GET /mail":
			return a.listMail(mail)
		case "GET /mail/{id}":
			return a.getMail(mail)
		case "DELETE /mail/{id}":
			return a.deleteMail(mail)
		}
	}
	return a.stub(pattern, rt)
}

func (a *API) ServeHTTP(w http.ResponseWriter, r *http.Request) { a.mux.ServeHTTP(w, r) }

// guard verifies the per-request signature for routes that require one.
func (a *API) guard(rt route, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(io.LimitReader(r.Body, maxBodyBytes+1))
		if err != nil || len(body) > maxBodyBytes {
			writeErr(w, http.StatusRequestEntityTooLarge, "body too large")
			return
		}
		r.Body = io.NopCloser(bytes.NewReader(body))

		if rt.by == sigNone {
			next.ServeHTTP(w, r)
			return
		}
		if err := a.verify(rt.by, r, body); err != nil {
			writeErr(w, http.StatusUnauthorized, err.Error())
			return
		}
		next.ServeHTTP(w, r)
	})
}

func (a *API) verify(class signer, r *http.Request, body []byte) error {
	keyID := r.Header.Get("Fount-Key-Id")
	tsRaw := r.Header.Get("Fount-Timestamp")
	nonce := r.Header.Get("Fount-Nonce")
	sigB64 := r.Header.Get("Fount-Signature")
	if keyID == "" || tsRaw == "" || nonce == "" || sigB64 == "" {
		return fmt.Errorf("missing signature headers")
	}
	ts, err := strconv.ParseInt(tsRaw, 10, 64)
	if err != nil {
		return fmt.Errorf("bad timestamp")
	}
	if d := time.Since(time.Unix(ts, 0)); d > timestampSkew || d < -timestampSkew {
		return fmt.Errorf("timestamp outside window")
	}
	if !a.nonces.useOnce(nonce, time.Unix(ts, 0)) {
		return fmt.Errorf("nonce replay")
	}
	sig, err := base64.StdEncoding.DecodeString(sigB64)
	if err != nil {
		return fmt.Errorf("bad signature encoding")
	}
	if a.resolver == nil {
		return fmt.Errorf("no key registered for %s (storage not yet live)", class)
	}
	pub, ok := a.resolver.Resolve(class, keyID)
	if !ok {
		return fmt.Errorf("unknown %s key", class)
	}
	sum := sha256.Sum256(body)
	canonical := fmt.Sprintf("%s\n%s\n%s\n%d\n%s", r.Method, r.URL.Path, hex.EncodeToString(sum[:]), ts, nonce)
	if !ed25519.Verify(pub, []byte(canonical), sig) {
		return fmt.Errorf("signature does not verify")
	}
	return nil
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

func writeErr(w http.ResponseWriter, code int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": msg})
}

// --- nonce replay cache ----------------------------------------------------

type nonceCache struct {
	mu   sync.Mutex
	seen map[string]time.Time
}

func newNonceCache() *nonceCache {
	c := &nonceCache{seen: make(map[string]time.Time)}
	return c
}

// useOnce records a nonce and returns false if it was already used within the
// retention window. Tied to the request timestamp so the window is bounded.
func (c *nonceCache) useOnce(nonce string, ts time.Time) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	now := time.Now()
	for k, t := range c.seen {
		if now.Sub(t) > nonceRetention {
			delete(c.seen, k)
		}
	}
	if _, ok := c.seen[nonce]; ok {
		return false
	}
	c.seen[nonce] = ts
	return true
}
