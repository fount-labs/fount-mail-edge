package deviceapi

import (
	"bytes"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/fount-labs/fount-mail-edge/internal/entitlement"
	"github.com/fount-labs/fount-mail-edge/internal/routing"
	"github.com/fount-labs/fount-mail-edge/internal/webauthn"
)

// maxOwners caps a PUT /routing owner list. The owner list is small by design
// (§14 sending limits); a cap keeps a signed request from bloating the object.
const maxOwners = 256

type addressRequest struct {
	Address        string `json:"address"`          // full worker address, e.g. "accountant.smithcpa@fountbox.com"
	DecryptionKey  []byte `json:"decryption_key"`   // X25519 public key mail is sealed to
	SigningKey     []byte `json:"signing_key"`      // Ed25519; this address's request-signing key
	OwnerChangeKey []byte `json:"owner_change_key"` // Ed25519
	PasskeyKey     []byte `json:"passkey_key"`      // passkey public key
	KeyChainSig    []byte `json:"key_chain_sig"`    // the parent mailbox key's signature over the key chain
}

// createAddress handles POST /address: a mailbox adds a worker address under the
// same license. The request is signed by the mailbox key (guard verified it),
// which also signs the new address's key chain (§5 "the mailbox key signs each
// address's public key"). The new address is its own routing record with its own
// per-address keys, but inherits the parent's mailbox key, license, and
// entitlement, so it is not a second mailbox for that license.
func (a *API) createAddress() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		parentID, ok := callerMailbox(r)
		if !ok {
			writeErr(w, http.StatusBadRequest, "bad key id")
			return
		}
		license, ok := a.mutator.LicenseOf(parentID)
		if !ok {
			writeErr(w, http.StatusNotFound, "no such mailbox")
			return
		}
		if !a.allowProbe(w, license) {
			return
		}
		var req addressRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeErr(w, http.StatusBadRequest, "bad request body")
			return
		}
		handle, ok := a.workerHandle(req.Address)
		if !ok {
			writeErr(w, http.StatusBadRequest, "invalid address")
			return
		}
		if !is32(req.DecryptionKey) || !is32(req.SigningKey) || !is32(req.OwnerChangeKey) {
			writeErr(w, http.StatusBadRequest, "keys must be 32 bytes")
			return
		}
		if !webauthn.ValidCredentialKey(req.PasskeyKey) {
			writeErr(w, http.StatusBadRequest, "passkey key must be a P-256 point")
			return
		}
		// The mailbox key authorizes the new address. guard already verified the
		// request signature against it; resolve it again to check the key chain.
		parentKey, ok := a.resolver.Resolve(sigMailbox, r.Header.Get("Fount-Key-Id"))
		if !ok {
			writeErr(w, http.StatusInternalServerError, "mailbox key unavailable")
			return
		}
		chain := keyChain(req.DecryptionKey, req.SigningKey, req.OwnerChangeKey, req.PasskeyKey)
		if !ed25519.Verify(parentKey, chain, req.KeyChainSig) {
			writeErr(w, http.StatusBadRequest, "key chain signature does not verify")
			return
		}

		id, err := a.mutator.AddAddress(r.Context(), routing.NewAddress{
			ParentMailboxID: parentID,
			Handle:          handle,
			Address:         req.Address,
			DecryptionKey:   req.DecryptionKey,
			SigningKey:      req.SigningKey,
			OwnerChangeKey:  req.OwnerChangeKey,
			PasskeyKey:      req.PasskeyKey,
			Log:             a.logKey(),
		})
		switch {
		case errors.Is(err, routing.ErrNotHandle):
			writeErr(w, http.StatusForbidden, "address is not under this handle")
			return
		case errors.Is(err, routing.ErrWorkerLimit):
			writeErr(w, http.StatusForbidden, "worker limit reached")
			return
		case errors.Is(err, routing.ErrKeyNotLogged):
			writeErr(w, http.StatusInternalServerError, "could not record key")
			return
		case errors.Is(err, routing.ErrHandleTaken):
			writeErr(w, http.StatusConflict, "address already registered")
			return
		case errors.Is(err, routing.ErrNoMailbox):
			writeErr(w, http.StatusNotFound, "no such mailbox")
			return
		case err != nil:
			writeFailure(w, err, "add address failed")
			return
		}
		writeJSON(w, http.StatusCreated, map[string]any{"mailbox_id": hex.EncodeToString(id)})
	})
}

type routingRequest struct {
	Version uint64   `json:"version"` // device-held routing version (§4), must be >= 1
	Owners  []string `json:"owners"`  // owner addresses; the edge stores only their keyed hashes
}

// putRouting handles PUT /routing: the owner-change key (guard verified) writes
// the versioned owner list. The edge keeps each owner as a keyed hash, plus a
// sealed copy for owner mail (§4), and queues the M3 owner notices (§10).
// The version must not go backwards, which is how a rolled-back routing object
// gets corrected on the next sync and an old owner set can't be replayed.
func (a *API) putRouting() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mailboxID, ok := callerMailbox(r)
		if !ok {
			writeErr(w, http.StatusBadRequest, "bad key id")
			return
		}
		var req routingRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeErr(w, http.StatusBadRequest, "bad request body")
			return
		}
		if req.Version == 0 {
			writeErr(w, http.StatusBadRequest, "version must be >= 1")
			return
		}
		if len(req.Owners) > maxOwners {
			writeErr(w, http.StatusBadRequest, "too many owners")
			return
		}
		for _, o := range req.Owners {
			if strings.TrimSpace(o) == "" {
				writeErr(w, http.StatusBadRequest, "empty owner address")
				return
			}
		}
		err := a.mutator.SetOwners(r.Context(), mailboxID, req.Version, req.Owners)
		switch {
		case errors.Is(err, routing.ErrStaleVersion):
			writeErr(w, http.StatusConflict, "routing version did not advance")
			return
		case errors.Is(err, routing.ErrOwnerLimit):
			w.Header().Set("Retry-After", "3600")
			writeErr(w, http.StatusTooManyRequests, "new-owner limit reached, retry later")
			return
		case errors.Is(err, routing.ErrNoMailbox):
			writeErr(w, http.StatusNotFound, "no such mailbox")
			return
		case err != nil:
			writeFailure(w, err, "write routing failed")
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"version": req.Version, "owners": len(req.Owners)})
	})
}

// renewEntitlement handles POST /entitlement: the address key (guard verified)
// presents a fresh entitlement, and the edge extends the mailbox's stored
// expiry. The renewal entitlement must name this mailbox's request-signing key
// and carry its license hash, so a token minted for another device or license
// can't extend this mailbox (§4 "renewal must not link a license to a mailbox"
// is upheld by never logging the link, only comparing the keyed hash).
func (a *API) renewEntitlement() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mailboxID, ok := callerMailbox(r)
		if !ok {
			writeErr(w, http.StatusBadRequest, "bad key id")
			return
		}
		if len(a.entVerify) != ed25519.PublicKeySize {
			writeErr(w, http.StatusUnauthorized, "entitlement verification not configured")
			return
		}
		tok := r.Header.Get("Fount-Entitlement")
		if tok == "" {
			writeErr(w, http.StatusUnauthorized, "missing entitlement")
			return
		}
		claims, err := entitlement.Verify(tok, a.entVerify, time.Now(), timestampSkew)
		if err != nil {
			writeErr(w, http.StatusUnauthorized, err.Error())
			return
		}
		signKey, ok := a.resolver.Resolve(sigAddress, r.Header.Get("Fount-Key-Id"))
		if !ok {
			writeErr(w, http.StatusInternalServerError, "signing key unavailable")
			return
		}
		if !bytes.Equal(claims.DeviceKey, signKey) {
			writeErr(w, http.StatusUnauthorized, "entitlement is for a different device key")
			return
		}
		err = a.mutator.RenewEntitlement(r.Context(), mailboxID, claims.LicenseHash, claims.ExpiresAt)
		switch {
		case errors.Is(err, routing.ErrLicenseMismatch):
			writeErr(w, http.StatusConflict, "entitlement license does not match mailbox")
			return
		case errors.Is(err, routing.ErrNoMailbox):
			writeErr(w, http.StatusNotFound, "no such mailbox")
			return
		case err != nil:
			writeFailure(w, err, "renew failed")
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"entitlement_exp": claims.ExpiresAt})
	})
}

// workerHandle returns the full address of the handle a worker address sits under.
// A worker is <label>.<handle>@domain, one dot, so a bare name can't be claimed here
// and reserved names stay reserved on both sides of the dot (§4).
func (a *API) workerHandle(address string) (string, bool) {
	local, ok := a.localPart(address)
	if !ok {
		return "", false
	}
	label, handle, _ := strings.Cut(local, ".")
	if !validHandle(label) || !validHandle(handle) {
		return "", false
	}
	return handle + a.mailDomain, true
}

// localPart splits a full address into its local part and reports whether it is
// a valid worker address in this domain. Unlike a handle (§4), a worker address
// may contain dots (e.g. "accountant.smithcpa"), but the same lowercase-ASCII,
// digit, and hyphen rule otherwise holds, with no leading or trailing dot.
func (a *API) localPart(address string) (string, bool) {
	if a.mailDomain == "" || !strings.HasSuffix(address, a.mailDomain) {
		return "", false
	}
	local := strings.TrimSuffix(address, a.mailDomain)
	if len(local) == 0 || len(local) > 64 || local[0] == '.' || local[len(local)-1] == '.' {
		return "", false
	}
	for i := 0; i < len(local); i++ {
		c := local[i]
		if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-' || c == '.') {
			return "", false
		}
	}
	return local, true
}
