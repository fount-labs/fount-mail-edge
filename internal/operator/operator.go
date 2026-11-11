// Package operator is how an operator changes routing data now that only enclaves
// hold its keys. The edge does the work itself, on requests signed with the
// operator's Ed25519 key, whose public half is OPERATOR_KEY in the measured config.
//
// Nothing secret crosses this channel: a mailbox's keys are public, and a backup is
// already sealed with ROUTING_DATA_KEY. So the operator doesn't verify the edge, and
// the signature is the only check that matters. It covers the operation, a one-use
// nonce the edge issued, and the exact payload bytes.
package operator

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"sync"
	"time"

	"github.com/fount-labs/fount-mail-edge/internal/routing"
)

// The operations, which are also the last part of each path.
const (
	OpInit      = "init"
	OpProvision = "provision"
	OpRestore   = "restore"
)

const (
	nonceTTL     = 5 * time.Minute
	maxNonces    = 32
	maxBodyBytes = 64 << 20 // a backup holds every mailbox
)

// BeginResponse carries a nonce for exactly one signed request.
type BeginResponse struct {
	Nonce string `json:"nonce"`
}

// Request is one signed operation. Payload is signed as sent, so the edge never
// re-encodes what it checks.
type Request struct {
	Nonce     string `json:"nonce"`
	Payload   []byte `json:"payload"`
	Signature []byte `json:"signature"`
}

// Message is what the operator signs.
func Message(op, nonce string, payload []byte) []byte {
	msg := []byte("fount-mail-edge/operator/v1\x00")
	for _, part := range []string{op, nonce} {
		msg = append(msg, part...)
		msg = append(msg, 0)
	}
	return append(msg, payload...)
}

// StatusResponse is GET /operator/status. Like the route, it's unauthenticated
// and holds nothing secret.
type StatusResponse struct {
	Routing State `json:"routing"`
	// ACMEAccount is the Let's Encrypt account URL, which CAA `accounturi` pins.
	// Absent until the edge's newAccount call has answered.
	ACMEAccount string `json:"acme_account,omitempty"`
	// Send is "on", or "off: <why>". Absent until the vault pull is done.
	Send string `json:"send,omitempty"`
	// SendKeysetCommitment is the held send keyset's, absent if it has none.
	SendKeysetCommitment string `json:"send_keyset_commitment,omitempty"`
}

// Handler serves the operator routes on the edge's shim listener.
type Handler struct {
	key         ed25519.PublicKey
	routing     *Routing
	acmeAccount func() string
	send        func() (state, commitment string)
	now         func() time.Time

	mu     sync.Mutex
	nonces map[string]time.Time
}

func NewHandler(key ed25519.PublicKey, r *Routing) *Handler {
	return &Handler{key: key, routing: r, now: time.Now, nonces: map[string]time.Time{}}
}

// SetACMEAccount names where /operator/status reads the ACME account URL from.
// Call it before serving.
func (h *Handler) SetACMEAccount(f func() string) { h.acmeAccount = f }

// SetSend names where /operator/status reads whether sending is on. Call it
// before serving.
func (h *Handler) SetSend(f func() (state, commitment string)) { h.send = f }

func (h *Handler) status(w http.ResponseWriter) {
	out := StatusResponse{Routing: h.routing.State()}
	if h.acmeAccount != nil {
		out.ACMEAccount = h.acmeAccount()
	}
	if h.send != nil {
		out.Send, out.SendKeysetCommitment = h.send()
	}
	writeJSON(w, http.StatusOK, out)
}

func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	switch {
	case r.Method == http.MethodGet && r.URL.Path == "/operator/status":
		h.status(w)
	case r.Method == http.MethodPost && r.URL.Path == "/operator/begin":
		h.begin(w)
	case r.Method == http.MethodPost && r.URL.Path == "/operator/"+OpInit:
		h.signed(w, r, OpInit)
	case r.Method == http.MethodPost && r.URL.Path == "/operator/"+OpProvision:
		h.signed(w, r, OpProvision)
	case r.Method == http.MethodPost && r.URL.Path == "/operator/"+OpRestore:
		h.signed(w, r, OpRestore)
	default:
		http.NotFound(w, r)
	}
}

func (h *Handler) begin(w http.ResponseWriter) {
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	nonce := hex.EncodeToString(raw)
	h.mu.Lock()
	now := h.now()
	for n, exp := range h.nonces {
		if now.After(exp) {
			delete(h.nonces, n)
		}
	}
	if len(h.nonces) >= maxNonces {
		h.mu.Unlock()
		writeError(w, http.StatusTooManyRequests, errors.New("too many outstanding nonces; wait a few minutes"))
		return
	}
	h.nonces[nonce] = now.Add(nonceTTL)
	h.mu.Unlock()
	writeJSON(w, http.StatusOK, BeginResponse{Nonce: nonce})
}

// consume spends a nonce. Only a correctly signed request reaches it, so a stranger
// can't burn the operator's nonces.
func (h *Handler) consume(nonce string) bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	exp, ok := h.nonces[nonce]
	delete(h.nonces, nonce)
	return ok && !h.now().After(exp)
}

func (h *Handler) signed(w http.ResponseWriter, r *http.Request, op string) {
	var req Request
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxBodyBytes)).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	if len(h.key) != ed25519.PublicKeySize || !ed25519.Verify(h.key, Message(op, req.Nonce, req.Payload), req.Signature) {
		log.Printf("operator: refused %s: not signed by OPERATOR_KEY", op)
		writeError(w, http.StatusForbidden, errors.New("not signed by OPERATOR_KEY"))
		return
	}
	if !h.consume(req.Nonce) {
		writeError(w, http.StatusForbidden, errors.New("nonce unknown, used, or expired; begin again"))
		return
	}
	log.Printf("operator: %s, signed", op)
	var (
		out any
		err error
	)
	switch op {
	case OpInit:
		err = h.routing.Init(r.Context())
		out = map[string]bool{"initialized": err == nil}
	case OpProvision:
		var p ProvisionPayload
		if err = strictJSON(req.Payload, &p); err == nil {
			var id []byte
			id, err = h.routing.Provision(r.Context(), p)
			out = map[string]string{"mailbox_id": hex.EncodeToString(id)}
		}
	case OpRestore:
		var p RestorePayload
		if err = strictJSON(req.Payload, &p); err == nil {
			out, err = h.routing.Restore(r.Context(), p)
		}
	}
	if err != nil {
		log.Printf("operator: %s failed: %v", op, err)
		writeError(w, statusOf(err), err)
		return
	}
	writeJSON(w, http.StatusOK, out)
}

func strictJSON(raw []byte, v any) error {
	if err := json.Unmarshal(raw, v); err != nil {
		return fmt.Errorf("%w: %w", errBadPayload, err)
	}
	return nil
}

func statusOf(err error) int {
	switch {
	case errors.Is(err, errBadPayload):
		return http.StatusBadRequest
	case errors.Is(err, ErrNotReady):
		return http.StatusServiceUnavailable
	case errors.Is(err, ErrWrongState), errors.Is(err, routing.ErrObjectExists), errors.Is(err, routing.ErrHandleTaken):
		return http.StatusConflict
	default:
		return http.StatusInternalServerError
	}
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeError(w http.ResponseWriter, status int, err error) {
	writeJSON(w, status, map[string]string{"error": err.Error()})
}
