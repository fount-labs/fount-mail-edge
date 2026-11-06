package deviceapi

import (
	"errors"
	"net/http"

	"github.com/fount-labs/fount-mail-edge/internal/store"
)

// getBoot handles GET /boots/:id (design §8). It is unsigned (sigNone): a boot's
// attestation is public — it carries only the boot's message-signing public key,
// which the broker checks a stored message's signature against, even after that
// enclave is gone (§9). The object outlives the boot, so a message signed by a
// retired boot stays verifiable.
func (a *API) getBoot(boots store.BootStore) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, err := boots.ReadBoot(r.Context(), r.PathValue("id"))
		if errors.Is(err, store.ErrNotFound) {
			writeErr(w, http.StatusNotFound, "no such boot")
			return
		}
		if err != nil {
			writeErr(w, http.StatusInternalServerError, "read boot failed")
			return
		}
		writeJSON(w, http.StatusOK, b)
	})
}
