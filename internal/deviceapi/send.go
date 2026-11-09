package deviceapi

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"

	"github.com/fount-labs/fount-mail-edge/internal/send"
)

// Sender sends a worker's message to its owners (design §14). send.Service
// implements it; nil leaves POST /send a 501 stub, which is how the live release
// keeps sending off.
type Sender interface {
	Send(ctx context.Context, mailboxID, raw []byte) ([]send.Result, error)
}

type sendRequest struct {
	Message []byte `json:"message"` // the whole RFC 5322 message, base64 in JSON
}

// sendMail handles POST /send. guard has verified the address key, so the caller
// is the worker named by Fount-Key-Id; send.Policy checks the message is from
// that worker and only to its owners.
func (a *API) sendMail() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mailboxID, ok := callerMailbox(r)
		if !ok {
			writeErr(w, http.StatusBadRequest, "bad key id")
			return
		}
		var req sendRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil || len(req.Message) == 0 {
			writeErr(w, http.StatusBadRequest, "bad request body")
			return
		}
		results, err := a.sender.Send(r.Context(), mailboxID, req.Message)
		switch {
		case errors.Is(err, send.ErrBadMessage):
			writeErr(w, http.StatusBadRequest, err.Error())
			return
		case errors.Is(err, send.ErrNoMailbox):
			writeErr(w, http.StatusNotFound, "no such mailbox")
			return
		case errors.Is(err, send.ErrRateLimited):
			w.Header().Set("Retry-After", "3600")
			writeErr(w, http.StatusTooManyRequests, err.Error())
			return
		case errors.Is(err, send.ErrLapsed), errors.Is(err, send.ErrPaused), errors.Is(err, send.ErrNotWorker),
			errors.Is(err, send.ErrNotOwner), errors.Is(err, send.ErrNotProven):
			writeErr(w, http.StatusForbidden, err.Error())
			return
		case err != nil:
			writeErr(w, http.StatusInternalServerError, "send failed")
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"results": results})
	})
}
