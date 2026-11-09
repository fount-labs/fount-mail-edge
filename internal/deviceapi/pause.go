package deviceapi

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"time"

	"github.com/fount-labs/fount-mail-edge/internal/routing"
	"github.com/fount-labs/fount-mail-edge/internal/webauthn"
)

// Pauser holds a worker's pause flag (design §8 POST /pause, §12). routing.Store
// implements it, and New picks it up from the Mutator.
//
// Paused stops work, not mail. SMTP still accepts and stores the worker's mail,
// because a bounce would lose client mail the sender can't see was refused, and
// the Device API's reads still work, so the home device keeps fetching and holds
// what arrives. GET /mail carries the flag, and the broker starts no job for a
// paused worker. POST /send refuses while paused. The owner notices still go.
type Pauser interface {
	SetPaused(ctx context.Context, mailboxID []byte, paused bool) error
	Paused(mailboxID []byte) bool
}

// pauseHash is what a pause challenge binds besides the mailbox: the state asked
// for, so an approval to pause can't be replayed as a resume. The label keeps it
// apart from recoveryHash, whose input is a length-framed key chain, so neither
// challenge passes for the other. GET /recover/{id} takes any kc, so it can mint
// a pause challenge too; that's harmless, because a challenge carries no
// authority until the worker's passkey signs it.
func pauseHash(paused bool) []byte {
	h := sha256.New()
	h.Write([]byte("fount-mail-edge/v1/pause\x00"))
	if paused {
		h.Write([]byte{1})
	} else {
		h.Write([]byte{0})
	}
	return h.Sum(nil)
}

// pauseLive reports whether pause can run: a Pauser, a passkey to check against
// (the Mutator), and a Relying Party id to verify assertions with.
func (a *API) pauseLive() bool {
	return a.pauser != nil && a.mutator != nil && a.recoverRPID != ""
}

// ownerControl returns the handler for an M3 owner-control route that's live, or
// nil for the stub.
func (a *API) ownerControl(pattern string) http.Handler {
	switch {
	case a.pauseLive() && pattern == "GET /pause/{id}":
		return a.issuePauseChallenge()
	case a.pauseLive() && pattern == "POST /pause":
		return a.pause()
	}
	return nil
}

// issuePauseChallenge handles GET /pause/{id}?paused=true|false. Like the
// recovery challenge it's unsigned, because the device asking may not hold the
// worker's keys, and reveals nothing: it's a short-lived MAC bound to the worker
// and the state asked for.
func (a *API) issuePauseChallenge() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mid, err := hex.DecodeString(r.PathValue("id"))
		if err != nil || len(mid) != 32 {
			writeErr(w, http.StatusBadRequest, "bad mailbox id")
			return
		}
		paused, ok := parsePaused(r.URL.Query().Get("paused"))
		if !ok {
			writeErr(w, http.StatusBadRequest, "paused must be true or false")
			return
		}
		exp := time.Now().Add(challengeTTL).Unix()
		writeJSON(w, http.StatusOK, map[string]any{
			"challenge":  base64.RawURLEncoding.EncodeToString(a.mintChallenge(mid, pauseHash(paused), exp)),
			"expires_at": exp,
		})
	})
}

func parsePaused(v string) (bool, bool) {
	switch v {
	case "true":
		return true, true
	case "false":
		return false, true
	}
	return false, false
}

type pauseRequest struct {
	Challenge []byte             `json:"challenge"` // the edge challenge from GET /pause/{id}
	Paused    *bool              `json:"paused"`    // the state asked for; required
	Assertion webauthn.Assertion `json:"assertion"` // the worker's passkey over the challenge
}

// pause handles POST /pause: the worker's registered passkey pauses or resumes
// it, from a device that need not be its home (§12). guard checked only the
// timestamp, as for POST /recover; this handler is the whole authorization:
//
//  1. the challenge is a valid, unexpired edge token for this worker and this
//     state, so a pause approval can't be replayed as a resume;
//  2. the worker's passkey signed a WebAuthn assertion over it.
//
// Then the nonce and the challenge are each spent once. Resuming needs the
// passkey too: pause is the brake on a home device that's gone wrong, so that
// device's keys can't release it.
func (a *API) pause() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mid, ok := callerMailbox(r)
		if !ok {
			writeErr(w, http.StatusBadRequest, "bad key id")
			return
		}
		var req pauseRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Paused == nil {
			writeErr(w, http.StatusBadRequest, "bad request body")
			return
		}
		if !a.validChallenge(req.Challenge, mid, pauseHash(*req.Paused), time.Now()) {
			writeErr(w, http.StatusUnauthorized, "challenge invalid or expired")
			return
		}
		passkey, ok := a.mutator.PasskeyOf(mid)
		if !ok {
			writeErr(w, http.StatusNotFound, "no such mailbox")
			return
		}
		if err := webauthn.Verify(passkey, req.Assertion, req.Challenge, a.recoverRPID, a.recoverOrigin); err != nil {
			writeErr(w, http.StatusUnauthorized, "passkey assertion did not verify")
			return
		}
		if err := a.spendNonce(r); err != nil {
			writeErr(w, nonceStatus(err), err.Error())
			return
		}
		if err := a.nonces.useOnce("challenge:"+hex.EncodeToString(req.Challenge), time.Now()); err != nil {
			writeErr(w, nonceStatus(err), "challenge already used")
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
