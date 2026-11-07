package deviceapi

import (
	"bytes"
	"crypto/ed25519"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"

	"github.com/fount-labs/fount-mail-edge/internal/routing"
	"github.com/fount-labs/fount-mail-edge/internal/webauthn"
)

// reservedHandles can't be registered (§4). abuse and postmaster deliver to a
// Fount-owned mailbox, so they're reserved here too.
var reservedHandles = map[string]bool{
	"support": true, "admin": true, "billing": true, "fount": true,
	"administrator": true, "hostmaster": true, "postmaster": true,
	"webmaster": true, "abuse": true, "security": true, "mta-sts": true,
}

// validHandle enforces §4's handle rules: lowercase ASCII letters, digits, and
// hyphen only (no dots, '+', or quoting), not reserved, bounded length.
func validHandle(name string) bool {
	if len(name) == 0 || len(name) > 64 || reservedHandles[name] {
		return false
	}
	for i := 0; i < len(name); i++ {
		c := name[i]
		if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-') {
			return false
		}
	}
	return true
}

// checkHandle answers GET /handle/{name} with whether the handle is free. The
// caller is authorized by a valid entitlement (an active subscription); the
// availability of a specific name leaks nothing about who owns a taken one.
func (a *API) checkHandle() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Throttle availability probes per entitlement license (§8) so one
		// subscription can't sweep the handle namespace. The guard has already
		// verified the entitlement, so the claims are present.
		if claims, ok := claimsFrom(r.Context()); ok && !a.allowProbe(w, claims.LicenseHash) {
			return
		}
		name := r.PathValue("name")
		if !validHandle(name) {
			writeJSON(w, http.StatusOK, map[string]any{"available": false, "valid": false})
			return
		}
		ok, err := a.provisioner.Available(r.Context(), name+a.mailDomain)
		if err != nil {
			writeErr(w, http.StatusInternalServerError, "availability check failed")
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"available": ok, "valid": true})
	})
}

type mailboxRequest struct {
	Handle         string `json:"handle"`           // local part, e.g. "worker"
	DecryptionKey  []byte `json:"decryption_key"`   // X25519 public key mail is sealed to
	SigningKey     []byte `json:"signing_key"`      // Ed25519; must equal the entitlement's device key
	MailboxKey     []byte `json:"mailbox_key"`      // Ed25519; signs the key chain
	OwnerChangeKey []byte `json:"owner_change_key"` // Ed25519
	PasskeyKey     []byte `json:"passkey_key"`      // passkey public key
	KeyChainSig    []byte `json:"key_chain_sig"`    // mailbox key's signature over the key chain
}

// createMailbox handles POST /mailbox. The entitlement (verified by guard) binds
// the device's request-signing key and carries the license's keyed hash; the
// body carries the mailbox's device-asserted public keys and the mailbox key's
// signature over them. The edge checks the key chain, binds the signing key to
// the entitlement, and registers the mailbox if the handle and license are free.
func (a *API) createMailbox() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		claims, ok := claimsFrom(r.Context())
		if !ok {
			writeErr(w, http.StatusInternalServerError, "missing entitlement claims")
			return
		}
		if !a.allowProbe(w, claims.LicenseHash) {
			return
		}
		var req mailboxRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeErr(w, http.StatusBadRequest, "bad request body")
			return
		}
		if !validHandle(req.Handle) {
			writeErr(w, http.StatusBadRequest, "invalid handle")
			return
		}
		if !is32(req.DecryptionKey) || !is32(req.SigningKey) || !is32(req.MailboxKey) || !is32(req.OwnerChangeKey) {
			writeErr(w, http.StatusBadRequest, "keys must be 32 bytes")
			return
		}
		if !webauthn.ValidCredentialKey(req.PasskeyKey) {
			writeErr(w, http.StatusBadRequest, "passkey key must be a P-256 point")
			return
		}
		// The entitlement authorizes exactly the request-signing key the device
		// proved it holds (guard verified the request signature against it).
		if !bytes.Equal(req.SigningKey, claims.DeviceKey) {
			writeErr(w, http.StatusBadRequest, "signing key is not the entitled device key")
			return
		}
		// §9: the edge encrypts only to a key the mailbox key has signed. Prove
		// the mailbox key authorizes this whole key chain before trusting it.
		chain := keyChain(req.DecryptionKey, req.SigningKey, req.OwnerChangeKey, req.PasskeyKey)
		if !ed25519.Verify(req.MailboxKey, chain, req.KeyChainSig) {
			writeErr(w, http.StatusBadRequest, "key chain signature does not verify")
			return
		}

		// Create records the initial mailbox key in the write-once log once the
		// handle and license are known to be free, so every legitimate key has an
		// auditable entry and the broker has a baseline (§9), and a refused request
		// adds nothing to someone else's log. Fail closed: a mailbox is never
		// created whose first key wasn't logged.
		id, err := a.provisioner.Create(r.Context(), routing.NewMailbox{
			Address:        req.Handle + a.mailDomain,
			LicenseHash:    claims.LicenseHash,
			DecryptionKey:  req.DecryptionKey,
			SigningKey:     req.SigningKey,
			MailboxKey:     req.MailboxKey,
			OwnerChangeKey: req.OwnerChangeKey,
			PasskeyKey:     req.PasskeyKey,
			EntitlementExp: claims.ExpiresAt,
			Log:            a.logKey(),
		})
		switch {
		case errors.Is(err, routing.ErrHandleTaken):
			writeErr(w, http.StatusConflict, "handle already registered")
			return
		case errors.Is(err, routing.ErrLicenseTaken):
			writeErr(w, http.StatusConflict, "license already has a mailbox")
			return
		case errors.Is(err, routing.ErrKeyNotLogged):
			writeErr(w, http.StatusInternalServerError, "could not record key")
			return
		case err != nil:
			writeFailure(w, err, "create failed")
			return
		}
		writeJSON(w, http.StatusCreated, map[string]any{"mailbox_id": hex.EncodeToString(id)})
	})
}

func is32(b []byte) bool { return len(b) == 32 }

// keyChain is the byte string the mailbox key signs to authorize a mailbox's
// keys: each key length-prefixed (2 bytes big-endian) in a fixed order. The
// device must produce the same bytes; this is part of the §8/§9 contract.
func keyChain(dec, sign, owner, passkey []byte) []byte {
	var b []byte
	for _, k := range [][]byte{dec, sign, owner, passkey} {
		var l [2]byte
		binary.BigEndian.PutUint16(l[:], uint16(len(k)))
		b = append(b, l[:]...)
		b = append(b, k...)
	}
	return b
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}
