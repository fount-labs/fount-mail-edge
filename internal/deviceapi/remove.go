package deviceapi

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"

	"github.com/fount-labs/fount-mail-edge/internal/routing"
)

// Remover takes a deleted worker's address out of routing (fount launch-plan X4).
// routing.Store implements it, and New picks it up from the Mutator.
type Remover interface {
	RemoveAddress(ctx context.Context, callerID, targetID []byte) error
	RemoveCoordinated(ctx context.Context, targetID []byte) error
}

// codeHandle refuses removing a handle's own address, which is never released.
const codeHandle = "handle"

type removeRequest struct {
	MailboxID string `json:"mailbox_id"` // hex
}

func readRemoveTarget(w http.ResponseWriter, r *http.Request) ([]byte, bool) {
	var req removeRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, "bad request body")
		return nil, false
	}
	mid, err := hex.DecodeString(req.MailboxID)
	if err != nil || len(mid) != 32 {
		writeErr(w, http.StatusBadRequest, "bad mailbox id")
		return nil, false
	}
	return mid, true
}

// postAddressRemove handles POST /address/remove: the mailbox key (guard
// verified it) removes a worker address under its handle. Fount-Key-Id may be
// any address of the handle, or the removed address itself, so a retry after a
// lost answer still verifies; it's 200 again. An address under another handle
// answers as one that doesn't exist (404).
func (a *API) postAddressRemove() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		caller, ok := callerMailbox(r)
		if !ok {
			writeErr(w, http.StatusBadRequest, "bad key id")
			return
		}
		mid, ok := readRemoveTarget(w, r)
		if !ok {
			return
		}
		a.answerRemove(w, mid, a.remover.RemoveAddress(r.Context(), caller, mid))
	})
}

// postCoordinatorRemove handles POST /coordinator/remove: the current
// coordinator removes an enrolled worker's address, as when its Cloud worker or
// team is deleted. Removed again is 200.
func (a *API) postCoordinatorRemove() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mid, ok := readRemoveTarget(w, r)
		if !ok {
			return
		}
		a.answerRemove(w, mid, a.remover.RemoveCoordinated(r.Context(), mid))
	})
}

func (a *API) answerRemove(w http.ResponseWriter, mid []byte, err error) {
	switch {
	case errors.Is(err, routing.ErrNoMailbox), errors.Is(err, routing.ErrNotHandle):
		writeErr(w, http.StatusNotFound, "no such mailbox")
	case errors.Is(err, routing.ErrIsHandle):
		writeAPIError(w, &apiError{http.StatusConflict, codeHandle, "a handle's own address isn't removed"})
	case errors.Is(err, routing.ErrCoordinated):
		writeAPIError(w, coordinatorOnly())
	case errors.Is(err, routing.ErrNotCoordinated):
		writeAPIError(w, &apiError{http.StatusConflict, codeNotCoordinated, "this mailbox is not under a coordinator"})
	case err != nil:
		writeFailure(w, err, "remove failed")
	default:
		writeJSON(w, http.StatusOK, map[string]any{"mailbox_id": hex.EncodeToString(mid), "removed": true})
	}
}
