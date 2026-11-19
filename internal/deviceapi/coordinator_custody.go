package deviceapi

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"

	"github.com/fount-labs/fount-mail-edge/internal/routing"
)

// Once a mailbox is under a coordinator, only the coordinator changes its keys,
// owners and pause (security review 2026-11-19, H1 and M1). The device-key and
// passkey routes refuse it (coordinatorOnly), and these coordinator-signed
// routes stand in for them.

// DecryptionKeyRotator replaces a worker's decryption key. routing.Store
// implements it, and New picks it up from the Mutator.
type DecryptionKeyRotator interface {
	RotateDecryptionKey(ctx context.Context, mailboxID, key []byte) error
}

type decryptionKeyRequest struct {
	MailboxID     string `json:"mailbox_id"`     // hex
	DecryptionKey string `json:"decryption_key"` // base64 X25519 public key
}

// postDecryptionKey handles POST /coordinator/decryption-key: the current
// coordinator rotates an enrolled worker's X25519 decryption key, as when a team
// admin who could have read it is removed. Mail stored from then on seals to the
// new key, so the old private key opens nothing new; the coordinator keeps the
// old one for mail already waiting.
func (a *API) postDecryptionKey() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req decryptionKeyRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeErr(w, http.StatusBadRequest, "bad request body")
			return
		}
		key, err := base64.StdEncoding.DecodeString(req.DecryptionKey)
		if err != nil || !is32(key) {
			writeErr(w, http.StatusBadRequest, "decryption_key must be a base64 X25519 public key")
			return
		}
		mid, ok := a.coordinatedTarget(w, req.MailboxID)
		if !ok {
			return
		}
		err = a.decRotator.RotateDecryptionKey(r.Context(), mid, key)
		switch {
		case errors.Is(err, routing.ErrNoMailbox):
			writeErr(w, http.StatusNotFound, "no such mailbox")
			return
		case errors.Is(err, routing.ErrSameDecryptionKey):
			writeErr(w, http.StatusConflict, err.Error())
			return
		case errors.Is(err, routing.ErrNotCoordinated):
			writeAPIError(w, &apiError{http.StatusConflict, codeNotCoordinated, "this mailbox is not under a coordinator"})
			return
		case err != nil:
			writeFailure(w, err, "rotate failed")
			return
		}
		sum := sha256.Sum256(key)
		writeJSON(w, http.StatusOK, map[string]any{"mailbox_id": hex.EncodeToString(mid), "decryption_key_sha256": hex.EncodeToString(sum[:])})
	})
}

type coordinatorRoutingRequest struct {
	MailboxID string `json:"mailbox_id"` // hex
	routingRequest
}

// postCoordinatorRouting handles POST /coordinator/routing: the current
// coordinator writes an enrolled worker's owner list, with the same version
// rule, limits and connect proofs as PUT /routing, which refuses an enrolled
// mailbox.
func (a *API) postCoordinatorRouting() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req coordinatorRoutingRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeErr(w, http.StatusBadRequest, "bad request body")
			return
		}
		mid, ok := a.coordinatedTarget(w, req.MailboxID)
		if !ok {
			return
		}
		a.writeOwners(w, r, mid, req.routingRequest)
	})
}

type coordinatorPauseRequest struct {
	MailboxID string `json:"mailbox_id"` // hex
	Paused    *bool  `json:"paused"`     // required
}

// postCoordinatorPause handles POST /coordinator/pause: the current coordinator
// pauses or resumes an enrolled worker, as POST /pause does with a worker's
// passkey for one that isn't enrolled. It's the same Paused flag, apart from
// the lapse pause.
func (a *API) postCoordinatorPause() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req coordinatorPauseRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Paused == nil {
			writeErr(w, http.StatusBadRequest, "bad request body")
			return
		}
		mid, ok := a.coordinatedTarget(w, req.MailboxID)
		if !ok {
			return
		}
		err := a.pauser.SetPaused(r.Context(), mid, *req.Paused)
		switch {
		case errors.Is(err, routing.ErrNoMailbox):
			writeErr(w, http.StatusNotFound, "no such mailbox")
			return
		case err != nil:
			writeFailure(w, err, "pause failed")
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"mailbox_id": hex.EncodeToString(mid), "paused": *req.Paused})
	})
}
