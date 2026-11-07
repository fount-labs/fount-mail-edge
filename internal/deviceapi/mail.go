package deviceapi

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"strconv"

	"github.com/fount-labs/fount-mail-edge/internal/store"
)

// callerMailbox returns the 32-byte mailbox id the request is authenticated as.
// For the address-class routes, Fount-Key-Id is hex(mailbox id) — the same id
// the message objects are keyed under (design §4 S3 layout, §9) — and guard has
// already verified the signature against the key resolved for it, so the header
// value is trusted here.
func callerMailbox(r *http.Request) ([]byte, bool) {
	id, err := hex.DecodeString(r.Header.Get("Fount-Key-Id"))
	if err != nil || len(id) != 32 {
		return nil, false
	}
	return id, true
}

func (a *API) listMail(mail store.MailReader) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mailboxID, ok := callerMailbox(r)
		if !ok {
			writeErr(w, http.StatusBadRequest, "bad key id")
			return
		}
		msgs, err := mail.List(r.Context(), mailboxID)
		if err != nil {
			writeErr(w, http.StatusInternalServerError, "list failed")
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"messages": msgs})
	})
}

// listGaps handles GET /gaps?after=<sequence>: the signed records for sequence
// numbers above after that hold no message. Each is an edge-signed token the broker
// verifies itself (§9). A full page means there may be more, from its last sequence.
func (a *API) listGaps() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mailboxID, ok := callerMailbox(r)
		if !ok {
			writeErr(w, http.StatusBadRequest, "bad key id")
			return
		}
		var after uint64
		if v := r.URL.Query().Get("after"); v != "" {
			var err error
			if after, err = strconv.ParseUint(v, 10, 64); err != nil {
				writeErr(w, http.StatusBadRequest, "bad after")
				return
			}
		}
		recs, err := a.gaps.Gaps(r.Context(), mailboxID, after)
		if err != nil {
			writeErr(w, http.StatusInternalServerError, "list failed")
			return
		}
		out := make([]string, len(recs))
		for i, rec := range recs {
			out[i] = string(rec)
		}
		writeJSON(w, http.StatusOK, map[string]any{"records": out})
	})
}

func (a *API) getMail(mail store.MailReader) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mailboxID, ok := callerMailbox(r)
		if !ok {
			writeErr(w, http.StatusBadRequest, "bad key id")
			return
		}
		obj, err := mail.Get(r.Context(), mailboxID, r.PathValue("id"))
		if errors.Is(err, store.ErrNotFound) {
			writeErr(w, http.StatusNotFound, "no such message")
			return
		}
		if err != nil {
			writeErr(w, http.StatusInternalServerError, "get failed")
			return
		}
		// The object is the whole signed §9 blob, including the ciphertext the
		// edge can't read; the broker verifies the signature and decrypts.
		w.Header().Set("Content-Type", "application/octet-stream")
		_, _ = w.Write(obj)
	})
}

func (a *API) deleteMail(mail store.MailReader) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mailboxID, ok := callerMailbox(r)
		if !ok {
			writeErr(w, http.StatusBadRequest, "bad key id")
			return
		}
		if err := mail.Delete(r.Context(), mailboxID, r.PathValue("id")); err != nil {
			if errors.Is(err, store.ErrNotFound) {
				writeErr(w, http.StatusNotFound, "no such message")
				return
			}
			writeErr(w, http.StatusInternalServerError, "delete failed")
			return
		}
		w.WriteHeader(http.StatusNoContent)
	})
}
