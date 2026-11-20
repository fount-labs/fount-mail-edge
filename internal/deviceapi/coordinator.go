package deviceapi

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strconv"

	"github.com/fount-labs/fount-mail-edge/internal/generation"
	"github.com/fount-labs/fount-mail-edge/internal/routing"
	"github.com/fount-labs/fount-mail-edge/internal/send"
)

// Coordination is the Cloud coordinator's state in routing data (fount
// launch-plan decision 18): the newest generation, and which mailboxes are
// enrolled under it. routing.Store implements it, and New picks it up from the
// Mutator.
//
// A generation is proved by a certificate the Cloud vault signs, binding the
// generation number to that coordinator's own Ed25519 key. The edge keeps the
// highest generation it has seen, and from then on:
//
//   - an enrolled mailbox's per-mailbox calls (address, mailbox and owner-change
//     keys) must carry Fount-Generation equal to it, covered by the signature;
//   - only that generation's key signs the coordinator routes.
//
// So a partitioned old coordinator is refused everywhere as soon as its successor
// has spoken once. The header is a fence against a stale coordinator, not an
// authority: anyone holding a mailbox's address key can read the generation.
// What only the coordinator can do is sign with the current coordinator key.
type Coordination interface {
	CurrentCoordinator() (gen uint64, key ed25519.PublicKey, ok bool)
	Coordinated(mailboxID []byte) bool
	AdvanceCoordinator(ctx context.Context, gen uint64, key []byte) error
	EnrollCoordinator(ctx context.Context, mailboxID []byte, gen uint64, key []byte) error
}

// generationHeader names the coordinator generation a request is made under. When
// present it's appended to the canonical string, so it can't be stripped or
// changed.
const generationHeader = "Fount-Generation"

// The machine-readable codes a refused coordinator call carries in "code".
const (
	codeStaleGeneration    = "stale_generation"    // a newer generation has spoken; stop
	codeUnknownGeneration  = "unknown_generation"  // newer than the edge has seen; POST /coordinator/generation first
	codeGenerationRequired = "generation_required" // the mailbox is enrolled; send Fount-Generation
	codeGenerationConflict = "generation_conflict" // this generation already has another key
	codeNotCoordinated     = "not_coordinated"     // the mailbox isn't enrolled under a coordinator
	codeCoordinatorOnly    = "coordinator_only"    // the mailbox is enrolled; only the coordinator's key changes it
)

// coordinatorOnly is the refusal of a device-key or passkey change on an
// enrolled mailbox. Once a mailbox is under a coordinator, the coordinator is
// its only key holder (security review 2026-11-19, H1): a passkey, owner-change
// key some device kept from before enrollment can't recover, pause, re-own or
// connect through it. The mailbox key still adds new addresses under the
// handle (fenced), which gives it nothing over the enrolled one.
func coordinatorOnly() *apiError {
	return &apiError{http.StatusConflict, codeCoordinatorOnly, "this mailbox is under a coordinator; only the coordinator's key changes it"}
}

// refuseCoordinated answers coordinatorOnly and reports true when mid is
// enrolled.
func (a *API) refuseCoordinated(w http.ResponseWriter, mid []byte) bool {
	if a.coord == nil || !a.coord.Coordinated(mid) {
		return false
	}
	writeAPIError(w, coordinatorOnly())
	return true
}

// apiError is a refusal with a status and a stable code.
type apiError struct {
	status int
	code   string
	msg    string
}

func (e *apiError) Error() string { return e.msg }

func staleGeneration() *apiError {
	return &apiError{http.StatusConflict, codeStaleGeneration, "a newer coordinator generation has taken over"}
}

func writeAPIError(w http.ResponseWriter, e *apiError) {
	writeJSON(w, e.status, map[string]string{"error": e.msg, "code": e.code})
}

// coordinationLive reports whether the coordinator routes can run: routing data
// to keep the generation in, and the authority key that signs certificates.
func (a *API) coordinationLive() bool {
	return a.coord != nil && len(a.authority) == ed25519.PublicKeySize
}

// coordinatorKeyFromID reads a coordinator route's Fount-Key-Id, which is the
// hex of the coordinator's own public key.
func coordinatorKeyFromID(r *http.Request) (ed25519.PublicKey, error) {
	k, err := hex.DecodeString(r.Header.Get("Fount-Key-Id"))
	if err != nil || len(k) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("coordinator key id must be the hex of an Ed25519 public key")
	}
	return k, nil
}

type coordKeyCtx struct{}

// callerCoordinator is the coordinator key guard verified the request against.
func callerCoordinator(r *http.Request) ed25519.PublicKey {
	k, _ := r.Context().Value(coordKeyCtx{}).(ed25519.PublicKey)
	return k
}

// verifyCoordinator checks a coordinator-class signature. The key is the key id
// itself, so a stale coordinator is told so (409) rather than "unknown key",
// once its signature has shown it holds that key.
func (a *API) verifyCoordinator(class signer, r *http.Request, canonical, sig []byte) (context.Context, error) {
	if a.coord == nil {
		return nil, fmt.Errorf("no coordinator routes (storage not yet live)")
	}
	pub, err := coordinatorKeyFromID(r)
	if err != nil {
		return nil, err
	}
	if !ed25519.Verify(pub, canonical, sig) {
		return nil, fmt.Errorf("signature does not verify")
	}
	if class == sigCoordinator {
		_, cur, ok := a.coord.CurrentCoordinator()
		if !ok || !cur.Equal(pub) {
			return nil, staleGeneration()
		}
	}
	return context.WithValue(r.Context(), coordKeyCtx{}, pub), nil
}

// fenced reports whether a signer class is held to the generation fence: the
// per-mailbox device keys, which a coordinator also holds. The mailbox key
// isn't: it stays with the device that made the handle, it only signs POST
// /address, and a new address is a record of its own with its own keys, so
// it's no authority over an enrolled address it's named under. Fencing it
// would only stop that device adding workers under its handle once the
// handle's own address moved to a coordinator.
func fenced(class signer) bool {
	return class == sigAddress || class == sigOwnerChange
}

// fence refuses a call on an enrolled mailbox that doesn't name the current
// generation, and any owner-change call on one at all: that key stays with
// devices, so on an enrolled mailbox it's no authority (coordinatorOnly).
// guard runs it after the signature verifies.
func (a *API) fence(r *http.Request, class signer) *apiError {
	if a.coord == nil {
		return nil
	}
	mid, ok := callerMailbox(r)
	if !ok || !a.coord.Coordinated(mid) {
		return nil
	}
	if class == sigOwnerChange {
		return coordinatorOnly()
	}
	cur, _, _ := a.coord.CurrentCoordinator()
	v := r.Header.Get(generationHeader)
	if v == "" {
		return &apiError{http.StatusConflict, codeGenerationRequired, "this mailbox is under a coordinator; name its generation in Fount-Generation"}
	}
	g, err := strconv.ParseUint(v, 10, 64)
	switch {
	case err != nil:
		return &apiError{http.StatusBadRequest, codeGenerationRequired, "bad Fount-Generation"}
	case g < cur:
		return staleGeneration()
	case g > cur:
		return &apiError{http.StatusConflict, codeUnknownGeneration, "the edge hasn't seen this generation; POST /coordinator/generation first"}
	}
	return nil
}

type certificateRequest struct {
	Certificate string `json:"certificate"` // generation.Cert, signed by the Cloud vault
}

func (a *API) readCertificate(w http.ResponseWriter, r *http.Request) (generation.Cert, bool) {
	var req certificateRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Certificate == "" {
		writeErr(w, http.StatusBadRequest, "bad request body")
		return generation.Cert{}, false
	}
	c, err := generation.Verify(req.Certificate, a.authority)
	if err != nil {
		writeErr(w, http.StatusForbidden, "generation certificate does not verify")
		return generation.Cert{}, false
	}
	return c, true
}

// writeGenerationFailure answers a failed advance or enrollment.
func writeGenerationFailure(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, routing.ErrStaleGeneration):
		writeAPIError(w, staleGeneration())
	case errors.Is(err, routing.ErrGenerationConflict):
		writeAPIError(w, &apiError{http.StatusConflict, codeGenerationConflict, "this generation already has another coordinator key"})
	case errors.Is(err, routing.ErrNoMailbox):
		writeErr(w, http.StatusNotFound, "no such mailbox")
	default:
		writeFailure(w, err, "could not record the generation")
	}
}

// putCoordinator handles PUT /coordinator: the mailbox's address key enrolls it
// under the coordinator generation the certificate proves, moving the edge's
// generation on if it's newer. Enrolling again under the current generation is a
// no-op, so a coordinator may repeat it.
func (a *API) putCoordinator() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mid, ok := callerMailbox(r)
		if !ok {
			writeErr(w, http.StatusBadRequest, "bad key id")
			return
		}
		c, ok := a.readCertificate(w, r)
		if !ok {
			return
		}
		if err := a.coord.EnrollCoordinator(r.Context(), mid, c.Generation, c.Key); err != nil {
			writeGenerationFailure(w, err)
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"mailbox_id": hex.EncodeToString(mid), "generation": c.Generation})
	})
}

// postGeneration handles POST /coordinator/generation: a coordinator, signing
// with the key its certificate names, moves the edge's generation on. A new
// coordinator calls it once at start, before anything else, and from then on
// every older generation is refused.
func (a *API) postGeneration() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c, ok := a.readCertificate(w, r)
		if !ok {
			return
		}
		if !callerCoordinator(r).Equal(ed25519.PublicKey(c.Key)) {
			writeErr(w, http.StatusForbidden, "the certificate is for another key")
			return
		}
		if err := a.coord.AdvanceCoordinator(r.Context(), c.Generation, c.Key); err != nil {
			writeGenerationFailure(w, err)
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"generation": c.Generation})
	})
}

// coordinatedTarget reads the mailbox a coordinator route acts on, and checks it
// is enrolled. It answers the request itself when it returns false.
func (a *API) coordinatedTarget(w http.ResponseWriter, hexID string) ([]byte, bool) {
	mid, err := hex.DecodeString(hexID)
	if err != nil || len(mid) != 32 {
		writeErr(w, http.StatusBadRequest, "bad mailbox id")
		return nil, false
	}
	if !a.coord.Coordinated(mid) {
		writeAPIError(w, &apiError{http.StatusConflict, codeNotCoordinated, "this mailbox is not under a coordinator"})
		return nil, false
	}
	return mid, true
}

// Lapser holds a worker's lapse pause (fount launch-plan decision 11).
// routing.Store implements it, and New picks it up from the Mutator.
type Lapser interface {
	SetLapsed(ctx context.Context, mailboxID []byte, lapsed bool) error
	Lapse(mailboxID []byte) (lapsed bool, holdUntil int64)
}

type lapseRequest struct {
	MailboxID string `json:"mailbox_id"` // hex
	Lapsed    *bool  `json:"lapsed"`     // required
}

// postLapse handles POST /coordinator/lapse: the coordinator pauses an enrolled
// worker when its account's past_due grace ends, and resumes it when the account
// pays. While paused for lapse the edge holds the worker's mail rather than
// bouncing it, until the entitlement's expiry plus the hold (30 days), and refuses
// its sends; reads still work, so the account can export. Only the current
// coordinator key may set it: it's a billing state, not the worker's own.
func (a *API) postLapse() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req lapseRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Lapsed == nil {
			writeErr(w, http.StatusBadRequest, "bad request body")
			return
		}
		mid, ok := a.coordinatedTarget(w, req.MailboxID)
		if !ok {
			return
		}
		err := a.lapser.SetLapsed(r.Context(), mid, *req.Lapsed)
		switch {
		case errors.Is(err, routing.ErrNoMailbox):
			writeErr(w, http.StatusNotFound, "no such mailbox")
			return
		case err != nil:
			writeFailure(w, err, "lapse failed")
			return
		}
		lapsed, until := a.lapser.Lapse(mid)
		writeJSON(w, http.StatusOK, map[string]any{"mailbox_id": hex.EncodeToString(mid), "lapsed": lapsed, "hold_until": until})
	})
}

// SigningKeyRotator replaces a worker's address signing key. routing.Store
// implements it, and New picks it up from the Mutator.
type SigningKeyRotator interface {
	RotateSigningKey(ctx context.Context, mailboxID []byte, key ed25519.PublicKey) error
}

// signingKeyLabel prefixes what the new key signs to prove it's held, so the
// proof can't be lifted from any other signature.
const signingKeyLabel = "fount-mail-edge/v1/signing-key\x00"

type signingKeyRequest struct {
	MailboxID  string `json:"mailbox_id"`  // hex
	SigningKey string `json:"signing_key"` // base64 Ed25519 public key
	Proof      string `json:"proof"`       // base64 signature by the new key
}

// SigningKeyProof is what the new key signs: the label, the mailbox id and the
// key itself.
func SigningKeyProof(mailboxID []byte, key ed25519.PublicKey) []byte {
	msg := append([]byte(signingKeyLabel), mailboxID...)
	return append(msg, key...)
}

// postSigningKey handles POST /coordinator/signing-key: the current coordinator
// rotates an enrolled worker's address signing key, as when a team admin who
// held it is removed (fount launch-plan decision 25). It's the coordinator's
// call, not the old key's, because the old key is the one being revoked. The new
// key proves it's held by signing SigningKeyProof. From the next request on, the
// old key gets 401 on every address-key route, /send included.
func (a *API) postSigningKey() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req signingKeyRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeErr(w, http.StatusBadRequest, "bad request body")
			return
		}
		key, err := base64.StdEncoding.DecodeString(req.SigningKey)
		if err != nil || len(key) != ed25519.PublicKeySize {
			writeErr(w, http.StatusBadRequest, "signing_key must be a base64 Ed25519 public key")
			return
		}
		proof, err := base64.StdEncoding.DecodeString(req.Proof)
		if err != nil || len(proof) != ed25519.SignatureSize {
			writeErr(w, http.StatusBadRequest, "bad proof")
			return
		}
		mid, ok := a.coordinatedTarget(w, req.MailboxID)
		if !ok {
			return
		}
		if !ed25519.Verify(key, SigningKeyProof(mid, key), proof) {
			writeErr(w, http.StatusForbidden, "the proof isn't the new key's")
			return
		}
		err = a.rotator.RotateSigningKey(r.Context(), mid, key)
		switch {
		case errors.Is(err, routing.ErrNoMailbox):
			writeErr(w, http.StatusNotFound, "no such mailbox")
			return
		case errors.Is(err, routing.ErrSameSigningKey):
			writeErr(w, http.StatusConflict, err.Error())
			return
		case errors.Is(err, routing.ErrNotCoordinated):
			writeAPIError(w, &apiError{http.StatusConflict, codeNotCoordinated, "this mailbox is not under a coordinator"})
			return
		case err != nil:
			writeFailure(w, err, "rotate failed")
			return
		}
		sum := sha256.Sum256(key)
		writeJSON(w, http.StatusOK, map[string]any{"mailbox_id": hex.EncodeToString(mid), "signing_key_sha256": hex.EncodeToString(sum[:])})
	})
}

// ChangesFeed lists coordinated mailboxes changed since a cursor. routing.Store
// implements it, and New picks it up from the Mutator.
type ChangesFeed interface {
	Changes(cursor string, limit int) (routing.ChangesPage, error)
}

// defaultChanges and maxChanges size one page of POST /coordinator/changes.
const (
	defaultChanges = 500
	maxChanges     = 1000
)

type changesRequest struct {
	Cursor string `json:"cursor"`
	Limit  int    `json:"limit"`
}

type changeEntry struct {
	MailboxID string `json:"mailbox_id"`
	Changed   uint64 `json:"changed"`
	Sequence  uint64 `json:"sequence"`
	Paused    bool   `json:"paused"`
	Lapsed    bool   `json:"lapsed"`
}

// postChanges handles POST /coordinator/changes: the mailboxes enrolled under a
// coordinator that changed since the cursor, across all of them in one request
// (new mail moves a mailbox's sequence). It's a POST so the cursor is in the
// signed body.
func (a *API) postChanges() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req changesRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Limit < 0 || req.Limit > maxChanges || len(req.Cursor) > 64 {
			writeErr(w, http.StatusBadRequest, "bad request body")
			return
		}
		if req.Limit == 0 {
			req.Limit = defaultChanges
		}
		page, err := a.changes.Changes(req.Cursor, req.Limit)
		if errors.Is(err, routing.ErrBadCursor) {
			writeErr(w, http.StatusBadRequest, "bad cursor")
			return
		}
		if err != nil {
			writeFailure(w, err, "changes failed")
			return
		}
		out := make([]changeEntry, len(page.Changes))
		for i, c := range page.Changes {
			out[i] = changeEntry{MailboxID: hex.EncodeToString(c.MailboxID), Changed: c.Changed, Sequence: c.Sequence, Paused: c.Paused, Lapsed: c.Lapsed}
		}
		writeJSON(w, http.StatusOK, map[string]any{"changes": out, "cursor": page.Cursor, "more": page.More, "reset": page.Reset})
	})
}

// InviteSender sends a team invite from a worker (send.Service.SendInvite).
// The Sender implements it where it can send; nil leaves POST
// /coordinator/invite 501.
type InviteSender interface {
	SendInvite(ctx context.Context, mailboxID, raw []byte) ([]send.Result, error)
}

// The codes a refused invite carries. Callers (the coordinator, and through
// it Desktop's "Email it") branch on them, so they don't change.
const (
	codeInviteLimit   = "invite_limit"   // the worker's InvitesPerDay is spent
	codeInviteRefused = "invite_refused" // not an invite's shape: one recipient, plain text, small
)

type inviteRequest struct {
	MailboxID string `json:"mailbox_id"` // hex
	Message   []byte `json:"message"`    // the whole RFC 5322 message, base64 in JSON
}

// postInvite handles POST /coordinator/invite: the current coordinator mails a
// team invite from an enrolled worker to someone who isn't one of its owners
// (fount launch-plan decision 26). /send would refuse them, since they haven't
// proved they read anything; here the coordinator's generation key stands in,
// and send.Policy.CheckInvite keeps it to one plain-text message to one
// address, InvitesPerDay per worker. It goes through the same send records as
// /send, marked "invite", so the worker's POST /sent/query finds it and a
// retry is answered from the record.
func (a *API) postInvite() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req inviteRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil || len(req.Message) == 0 {
			writeErr(w, http.StatusBadRequest, "bad request body")
			return
		}
		mid, ok := a.coordinatedTarget(w, req.MailboxID)
		if !ok {
			return
		}
		results, err := a.inviter.SendInvite(r.Context(), mid, req.Message)
		switch {
		case errors.Is(err, send.ErrInviteLimit):
			w.Header().Set("Retry-After", "3600")
			writeAPIError(w, &apiError{http.StatusTooManyRequests, codeInviteLimit, err.Error()})
			return
		case errors.Is(err, send.ErrNotInvite), errors.Is(err, send.ErrNotOwner):
			writeAPIError(w, &apiError{http.StatusBadRequest, codeInviteRefused, err.Error()})
			return
		}
		writeSendResult(w, results, err)
	})
}
