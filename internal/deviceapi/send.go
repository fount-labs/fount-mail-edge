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
// keeps sending off. A Sender whose signer is off answers send.ErrOff, also 501.
type Sender interface {
	Send(ctx context.Context, mailboxID, raw []byte) ([]send.Result, error)
}

// SentLookup answers "was this Message-ID sent?" (POST /sent/query). The
// Sender implements it where it keeps send records; nil leaves the route 501.
type SentLookup interface {
	Lookup(ctx context.Context, mailboxID []byte, messageID string) (send.SentStatus, error)
}

type sendRequest struct {
	Message []byte `json:"message"` // the whole RFC 5322 message, base64 in JSON
}

// sendMail handles POST /send. guard has verified the address key, so the caller
// is the worker named by Fount-Key-Id; send.Policy checks the message is from
// that worker and only to its owners.
//
// A retry resends the same message, Message-ID and all: send.Dedupe answers it
// with the first send's results and re-attempts only Temporary recipients. The
// nonce cache can't do that, as a retry is a newly signed request.
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
		case errors.Is(err, send.ErrOff):
			// A split edge's mail-send has sending off: the same answer as no Sender.
			writeErr(w, http.StatusNotImplemented, "sending is off")
			return
		case errors.Is(err, send.ErrNoMailbox):
			writeErr(w, http.StatusNotFound, "no such mailbox")
			return
		case errors.Is(err, send.ErrSendInProgress):
			// The first send of this Message-ID is still being delivered.
			w.Header().Set("Retry-After", "30")
			writeErr(w, http.StatusConflict, err.Error())
			return
		case errors.Is(err, send.ErrMessageIDReused):
			writeErr(w, http.StatusConflict, err.Error())
			return
		case errors.Is(err, send.ErrSendInDoubt):
			writeAPIError(w, &apiError{http.StatusConflict, "send_in_doubt", err.Error()})
			return
		case errors.Is(err, send.ErrRecordFailed):
			w.Header().Set("Retry-After", "5")
			writeErr(w, http.StatusServiceUnavailable, "could not record the send; nothing was sent")
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

// maxSentQuery bounds one POST /sent/query.
const maxSentQuery = 100

type sentQuery struct {
	MessageIDs []string `json:"message_ids"`
}

// querySent handles POST /sent/query: for each Message-ID, what the edge knows of
// its send from the calling worker (send.SentStatus), in the order asked. It's a
// POST so the Message-IDs are in the signed body. A coordinator asks before it
// retries a send whose outcome it didn't record (fount launch-plan decision 14).
func (a *API) querySent() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mailboxID, ok := callerMailbox(r)
		if !ok {
			writeErr(w, http.StatusBadRequest, "bad key id")
			return
		}
		var q sentQuery
		if err := json.NewDecoder(r.Body).Decode(&q); err != nil || len(q.MessageIDs) == 0 || len(q.MessageIDs) > maxSentQuery {
			writeErr(w, http.StatusBadRequest, "message_ids must list 1 to 100 Message-IDs")
			return
		}
		out := make([]send.SentStatus, 0, len(q.MessageIDs))
		for _, id := range q.MessageIDs {
			if id == "" || len(id) > 998 {
				writeErr(w, http.StatusBadRequest, "bad Message-ID")
				return
			}
			st, err := a.sentLookup.Lookup(r.Context(), mailboxID, id)
			if err != nil {
				w.Header().Set("Retry-After", "5")
				writeErr(w, http.StatusServiceUnavailable, "could not read send records")
				return
			}
			out = append(out, st)
		}
		writeJSON(w, http.StatusOK, map[string]any{"records": out})
	})
}
