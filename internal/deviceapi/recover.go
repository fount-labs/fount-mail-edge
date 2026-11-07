package deviceapi

import (
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"time"

	"github.com/fount-labs/fount-mail-edge/internal/routing"
	"github.com/fount-labs/fount-mail-edge/internal/webauthn"
)

// challengeTTL bounds how long a recovery challenge is valid. It must cover a
// user tapping their passkey, no longer; a verified POST also spends its nonce.
const challengeTTL = 2 * time.Minute

// challengeLen is the stateless challenge token: an 8-byte big-endian expiry
// followed by its HMAC-SHA256 tag.
const challengeLen = 8 + sha256.Size

// recoveryHash is the kc a recovery challenge binds: the new key chain and the new
// mailbox key. The chain alone isn't enough, because the mailbox key signs it rather
// than appearing in it. The chain's framing is fixed, so the join is unambiguous.
func recoveryHash(chain, mailboxKey []byte) []byte {
	h := sha256.New()
	h.Write(chain)
	h.Write(mailboxKey)
	return h.Sum(nil)
}

// mintChallenge issues a stateless recovery challenge bound to a mailbox and the
// exact new keys it authorizes. The token is exp || HMAC(recoverKey, mid || kc ||
// exp); because the MAC covers kc (recoveryHash of the new keys), a passkey
// assertion over this challenge can only approve these new keys, not a set a
// man-in-the-middle swapped in. The recoverKey is per boot, so a challenge never
// outlives the enclave that issued it.
func (a *API) mintChallenge(mid, kc []byte, exp int64) []byte {
	var expBytes [8]byte
	binary.BigEndian.PutUint64(expBytes[:], uint64(exp))
	mac := hmac.New(sha256.New, a.recoverKey)
	mac.Write(mid)
	mac.Write(kc)
	mac.Write(expBytes[:])
	tok := make([]byte, 0, challengeLen)
	tok = append(tok, expBytes[:]...)
	return mac.Sum(tok)
}

// validChallenge checks a presented challenge token is well-formed, unexpired,
// and bound to this mailbox and new key chain.
func (a *API) validChallenge(tok, mid, kc []byte, now time.Time) bool {
	if len(tok) != challengeLen {
		return false
	}
	exp := int64(binary.BigEndian.Uint64(tok[:8]))
	if now.Unix() > exp {
		return false
	}
	want := a.mintChallenge(mid, kc, exp)
	return subtle.ConstantTimeCompare(tok, want) == 1
}

// issueRecoveryChallenge handles GET /recover/{id}?kc=<hex>. It is unsigned: a
// lost device has no key, and the challenge reveals nothing (it is an opaque
// MAC). {id} is the hex mailbox id; kc is the recoveryHash of the keys the device
// intends to install, so the challenge binds the passkey approval to those exact
// keys.
func (a *API) issueRecoveryChallenge() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mid, err := hex.DecodeString(r.PathValue("id"))
		if err != nil || len(mid) != 32 {
			writeErr(w, http.StatusBadRequest, "bad mailbox id")
			return
		}
		kc, err := hex.DecodeString(r.URL.Query().Get("kc"))
		if err != nil || len(kc) != sha256.Size {
			writeErr(w, http.StatusBadRequest, "bad key chain hash")
			return
		}
		exp := time.Now().Add(challengeTTL).Unix()
		writeJSON(w, http.StatusOK, map[string]any{
			"challenge":  base64.RawURLEncoding.EncodeToString(a.mintChallenge(mid, kc, exp)),
			"expires_at": exp,
		})
	})
}

// spendNonce records the nonce on a request guard has already timestamp-checked.
func (a *API) spendNonce(r *http.Request) error {
	ts, err := strconv.ParseInt(r.Header.Get("Fount-Timestamp"), 10, 64)
	if err != nil {
		return fmt.Errorf("bad timestamp")
	}
	return a.nonces.useOnce(r.Header.Get("Fount-Nonce"), time.Unix(ts, 0))
}

type recoverRequest struct {
	Challenge      []byte             `json:"challenge"`        // the edge challenge token from GET /recover/{id}
	DecryptionKey  []byte             `json:"decryption_key"`   // new X25519 public key
	SigningKey     []byte             `json:"signing_key"`      // new Ed25519 request-signing key
	MailboxKey     []byte             `json:"mailbox_key"`      // new Ed25519 mailbox key
	OwnerChangeKey []byte             `json:"owner_change_key"` // new Ed25519 owner-change key
	PasskeyKey     []byte             `json:"passkey_key"`      // new passkey credential key (P-256 SEC1)
	KeyChainSig    []byte             `json:"key_chain_sig"`    // new mailbox key's signature over the new chain
	Assertion      webauthn.Assertion `json:"assertion"`        // the registered passkey's assertion over the challenge
}

// recover handles POST /recover: after a lost device, the mailbox's registered
// passkey approves rotating to a new key set on the same handle (§5). guard has
// already checked the timestamp (there is no device signature — the device is
// gone); this handler is the whole authorization:
//
//  1. the challenge is a valid, unexpired edge token bound to this mailbox and
//     the exact new keys, mailbox key included (so a swapped key is rejected);
//  2. the new mailbox key signs the new key chain (the keys are self-consistent);
//  3. the registered passkey signed a WebAuthn assertion over that challenge
//     (the real owner, not the host, approved this).
//
// Only then does it spend the nonce and the challenge, each once, so
// unauthenticated requests can't fill the cache, and rotate. RotateKeys writes the
// new mailbox key to the write-once log first, and that must succeed, so a key is
// never made live without being auditable (§9).
func (a *API) recover() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mid, ok := callerMailbox(r)
		if !ok {
			writeErr(w, http.StatusBadRequest, "bad key id")
			return
		}
		var req recoverRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeErr(w, http.StatusBadRequest, "bad request body")
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

		// The challenge binds the approval to exactly these new keys.
		chain := keyChain(req.DecryptionKey, req.SigningKey, req.OwnerChangeKey, req.PasskeyKey)
		if !a.validChallenge(req.Challenge, mid, recoveryHash(chain, req.MailboxKey), time.Now()) {
			writeErr(w, http.StatusUnauthorized, "challenge invalid or expired")
			return
		}
		// The new mailbox key authorizes its own new key chain (as at creation).
		if !ed25519.Verify(req.MailboxKey, chain, req.KeyChainSig) {
			writeErr(w, http.StatusBadRequest, "key chain signature does not verify")
			return
		}
		// The registered passkey approves the rotation.
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
		// The nonce is the caller's choice, so it can't stop an approval being
		// resent. The challenge's lifetime is shorter than the cache's retention.
		if err := a.nonces.useOnce("challenge:"+hex.EncodeToString(req.Challenge), time.Now()); err != nil {
			writeErr(w, nonceStatus(err), "challenge already used")
			return
		}

		_, err := a.mutator.RotateKeys(r.Context(), mid, routing.RotatedKeys{
			DecryptionKey:  req.DecryptionKey,
			SigningKey:     req.SigningKey,
			MailboxKey:     req.MailboxKey,
			OwnerChangeKey: req.OwnerChangeKey,
			PasskeyKey:     req.PasskeyKey,
			Log:            a.logKey(),
		})
		switch {
		case errors.Is(err, routing.ErrNoMailbox):
			writeErr(w, http.StatusNotFound, "no such mailbox")
			return
		case errors.Is(err, routing.ErrKeyNotLogged):
			writeErr(w, http.StatusInternalServerError, "could not record key")
			return
		case err != nil:
			writeFailure(w, err, "rotate failed")
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"mailbox_id": hex.EncodeToString(mid), "rotated": true})
	})
}
