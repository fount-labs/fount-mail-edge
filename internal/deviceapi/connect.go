package deviceapi

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"time"

	"github.com/fount-labs/fount-mail-edge/internal/notice"
	"github.com/fount-labs/fount-mail-edge/internal/send"
)

// Connector mails a would-be owner from a worker's own address (POST /connect).
// notice.Connector implements it; nil means sending is off.
type Connector interface {
	Connect(ctx context.Context, mailboxID []byte, address, owner string) (expiresAt time.Time, err error)
}

var _ Connector = (*notice.Connector)(nil)

type connectRequest struct {
	Address string `json:"address"` // the worker's own address, which the mail is from
	Owner   string `json:"owner"`
}

// connect handles POST /connect. guard has verified the owner-change key, the
// key that later writes the owner on PUT /routing. The answer carries only when
// the proof expires: the device learns the Message-ID from the owner's reply,
// never from the edge, so it can't prove an owner who didn't reply.
func (a *API) connect() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mailboxID, ok := callerMailbox(r)
		if !ok {
			writeErr(w, http.StatusBadRequest, "bad key id")
			return
		}
		var req connectRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeErr(w, http.StatusBadRequest, "bad request body")
			return
		}
		if a.connector == nil {
			writeErr(w, http.StatusServiceUnavailable, "sending is off")
			return
		}
		exp, err := a.connector.Connect(r.Context(), mailboxID, req.Address, req.Owner)
		var limited *notice.ConnectLimitError
		switch {
		case errors.Is(err, notice.ErrConnectNotWorker):
			writeErr(w, http.StatusNotFound, err.Error())
			return
		case errors.Is(err, notice.ErrConnectBadOwner):
			writeErr(w, http.StatusBadRequest, err.Error())
			return
		case errors.Is(err, send.ErrOff):
			writeErr(w, http.StatusServiceUnavailable, "sending is off")
			return
		case errors.As(err, &limited):
			w.Header().Set("Retry-After", strconv.Itoa(max(1, int(limited.Wait.Seconds()))))
			writeErr(w, http.StatusTooManyRequests, err.Error())
			return
		case errors.Is(err, notice.ErrConnectUndelivered):
			writeErr(w, http.StatusBadGateway, err.Error())
			return
		case err != nil:
			writeErr(w, http.StatusInternalServerError, "connect failed")
			return
		}
		writeJSON(w, http.StatusAccepted, map[string]any{"expiresAt": exp.Unix()})
	})
}
