package operator

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"strings"
	"sync"
	"time"

	"github.com/fount-labs/fount-mail-edge/internal/routing"
	"github.com/fount-labs/fount-mail-edge/internal/store"
	"github.com/fount-labs/fount-mail-edge/internal/webauthn"
)

// State is where the edge is in its boot, as /operator/status reports it.
type State string

const (
	StateNoKeys     State = "waiting-for-keys"
	StateNoObject   State = "no-routing-object"  // waiting for init or restore
	StateCorrupt    State = "routing-unreadable" // waiting for a restore with replace
	StateServing    State = "serving"
	StateRestarting State = "restarting"
)

var (
	ErrNotReady   = errors.New("operator: the edge isn't ready for that yet")
	ErrWrongState = errors.New("operator: not allowed in this state")
	errBadPayload = errors.New("operator: bad payload")
)

// roles are the addresses provision may create. It's deliberately no wider: the
// reserved list exists to keep every other name unregistered.
var roles = map[string]bool{"abuse": true, "postmaster": true}

// PublicKeys are a mailbox's public keys, with the field names of POST /mailbox.
// They come from the device that reads the mailbox, which holds the private halves.
type PublicKeys struct {
	DecryptionKey  []byte `json:"decryption_key"`
	SigningKey     []byte `json:"signing_key"`
	MailboxKey     []byte `json:"mailbox_key"`
	OwnerChangeKey []byte `json:"owner_change_key"`
	PasskeyKey     []byte `json:"passkey_key"`
}

// ProvisionPayload adds a Fount-owned mailbox for abuse@ or postmaster@ (§4). The
// Device API refuses those names, so nobody else can register them.
type ProvisionPayload struct {
	Role string     `json:"role"`
	Keys PublicKeys `json:"keys"`
}

// RestorePayload installs a routing backup. Without Write it only verifies the
// backup and reports what it holds.
type RestorePayload struct {
	Backup []byte `json:"backup"`
	// BootRecord is the signing boot's record, if edge/boots no longer has it.
	BootRecord []byte `json:"boot_record,omitempty"`
	// SkipSequences moves every counter forward; see routing.Restore.
	SkipSequences uint64 `json:"skip_sequences"`
	Write         bool   `json:"write"`
	Replace       bool   `json:"replace"`
}

// RestoreResult is what the backup held, and whether it was installed.
type RestoreResult struct {
	BootID     string `json:"boot_id"`
	Generation int    `json:"generation"`
	Mailboxes  int    `json:"mailboxes"`
	Sequences  uint64 `json:"sequence_total"`
	Written    bool   `json:"written"`
	Restarting bool   `json:"restarting"`
}

// Backend is what the routing operations need once the edge has its keys.
type Backend struct {
	Blobs          routing.Blobs
	RoutingDataKey []byte
	MailDomain     string
}

// Routing tracks the edge's routing data through boot, and runs the operations
// that would otherwise need someone outside the enclave to hold its keys. One
// operation runs at a time.
type Routing struct {
	mu      sync.Mutex
	state   State
	be      Backend
	live    *routing.Store
	keylog  store.KeyLog
	drain   func(context.Context)
	loaded  chan struct{} // an init or restore made the object loadable
	restart chan struct{} // closed when the edge must restart to load a restore
}

func NewRouting() *Routing {
	return &Routing{state: StateNoKeys, loaded: make(chan struct{}, 1), restart: make(chan struct{})}
}

func (r *Routing) State() State {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.state
}

// Restart is closed when a restore has replaced the object a serving edge loaded.
// The edge then exits, and its restart policy boots it against the restored one.
func (r *Routing) Restart() <-chan struct{} { return r.restart }

// Load opens the routing object, and waits for an operator if it's missing or
// unreadable rather than exiting: a restart would come back to the same state,
// and would have to wait for the vault each time. Any other error is returned.
func (r *Routing) Load(ctx context.Context, be Backend, open func(context.Context) (*routing.Store, error)) (*routing.Store, error) {
	r.mu.Lock()
	r.be = be
	r.mu.Unlock()
	for {
		s, err := open(ctx)
		var waiting State
		switch {
		case err == nil:
			return s, nil
		case errors.Is(err, routing.ErrNoObject):
			waiting = StateNoObject
		case errors.Is(err, routing.ErrCorrupt):
			waiting = StateCorrupt
		default:
			return nil, err
		}
		r.mu.Lock()
		r.state = waiting
		r.mu.Unlock()
		log.Printf("operator: %v; waiting for a signed edgectl request", err)
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-r.loaded:
		}
	}
}

// Serve records the loaded store. drain stops SMTP and the Device API, for a
// restore that replaces the object this edge is serving from.
func (r *Routing) Serve(live *routing.Store, keylog store.KeyLog, drain func(context.Context)) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.live, r.keylog, r.drain = live, keylog, drain
	r.state = StateServing
}

// Init writes the empty routing object for a new deployment. It refuses to
// replace an object, so it's only useful the first time an edge boots.
func (r *Routing) Init(ctx context.Context) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	switch r.state {
	case StateNoObject:
	case StateNoKeys, StateRestarting:
		return ErrNotReady
	default:
		return routing.ErrObjectExists
	}
	if err := routing.Initialize(ctx, r.be.Blobs, r.be.RoutingDataKey); err != nil {
		return err
	}
	r.signalLoaded()
	return nil
}

// Provision adds a role mailbox through the live store, so it takes effect at once.
func (r *Routing) Provision(ctx context.Context, p ProvisionPayload) ([]byte, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.state != StateServing {
		return nil, fmt.Errorf("%w: provisioning needs a serving edge, and it's %s", ErrWrongState, r.state)
	}
	m, err := NewMailbox(p.Role, r.be.MailDomain, p.Keys)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", errBadPayload, err)
	}
	if r.keylog != nil {
		m.Log = func(ctx context.Context, id, keyHash []byte) error {
			return r.keylog.AppendMailboxKeyHash(ctx, hex.EncodeToString(id), keyHash, time.Now().Unix())
		}
	}
	return r.live.Create(ctx, m)
}

// Restore verifies a backup and, with Write, installs it. A serving edge stops
// taking mail first, and restarts afterwards, because what it holds in memory is
// the state the restore is undoing.
func (r *Routing) Restore(ctx context.Context, p RestorePayload) (RestoreResult, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.state == StateNoKeys || r.state == StateRestarting {
		return RestoreResult{}, ErrNotReady
	}
	bootID, err := routing.BackupBootID(p.Backup)
	if err != nil {
		return RestoreResult{}, fmt.Errorf("%w: %w", errBadPayload, err)
	}
	record, err := bootRecord(ctx, r.be.Blobs, p.BootRecord, hex.EncodeToString(bootID))
	if err != nil {
		return RestoreResult{}, err
	}
	object, err := routing.OpenBackup(p.Backup, record.SigningKey)
	if err != nil {
		return RestoreResult{}, fmt.Errorf("%w: %w", errBadPayload, err)
	}
	rs := routing.Restore{Object: object, RoutingDataKey: r.be.RoutingDataKey, SkipSequences: p.SkipSequences, Replace: p.Replace}
	sum, err := rs.Inspect()
	if err != nil {
		return RestoreResult{}, fmt.Errorf("%w: %w", errBadPayload, err)
	}
	res := RestoreResult{BootID: hex.EncodeToString(bootID), Generation: sum.Generation, Mailboxes: sum.Mailboxes, Sequences: sum.Sequences}
	if !p.Write {
		return res, nil
	}
	if r.state != StateNoObject && !p.Replace {
		return res, routing.ErrObjectExists
	}
	if r.state == StateServing {
		log.Printf("operator: draining SMTP and the Device API for a restore")
		r.drain(ctx)
		r.state = StateRestarting
		defer close(r.restart) // even on failure: nothing is serving any more
		res.Restarting = true
	}
	sum, err = rs.Apply(ctx, r.be.Blobs)
	if err != nil {
		return res, err
	}
	res.Generation, res.Sequences, res.Written = sum.Generation, sum.Sequences, true
	if !res.Restarting {
		r.signalLoaded()
	}
	return res, nil
}

func (r *Routing) signalLoaded() {
	select {
	case r.loaded <- struct{}{}:
	default:
	}
}

// bootRecord finds the key that signed a backup: the copy the operator sent, when
// edge/boots no longer has it, and otherwise the mail bucket's.
func bootRecord(ctx context.Context, blobs store.Blobs, sent []byte, bootID string) (store.Boot, error) {
	raw := sent
	if raw == nil {
		var err error
		if raw, err = blobs.Get(ctx, "edge/boots/"+bootID); err != nil {
			return store.Boot{}, fmt.Errorf("boot record %s: %w", bootID, err)
		}
	}
	var b store.Boot
	if err := json.Unmarshal(raw, &b); err != nil {
		return store.Boot{}, fmt.Errorf("%w: boot record %s: %w", errBadPayload, bootID, err)
	}
	if b.BootID != bootID {
		return store.Boot{}, fmt.Errorf("%w: boot record is for %s, want %s", errBadPayload, b.BootID, bootID)
	}
	return b, nil
}

// NewMailbox builds a role mailbox's record. It has no license and no entitlement
// expiry, so it doesn't count against anyone's license and never lapses.
func NewMailbox(role, domain string, k PublicKeys) (routing.NewMailbox, error) {
	if !roles[role] {
		return routing.NewMailbox{}, fmt.Errorf("role %q: want abuse or postmaster", role)
	}
	if !strings.HasPrefix(domain, "@") {
		domain = "@" + domain
	}
	for _, key := range [][]byte{k.DecryptionKey, k.SigningKey, k.MailboxKey, k.OwnerChangeKey} {
		if len(key) != 32 {
			return routing.NewMailbox{}, errors.New("keys must be 32 bytes")
		}
	}
	if !webauthn.ValidCredentialKey(k.PasskeyKey) {
		return routing.NewMailbox{}, errors.New("passkey key must be a P-256 point")
	}
	return routing.NewMailbox{
		Address:        role + domain,
		DecryptionKey:  k.DecryptionKey,
		SigningKey:     k.SigningKey,
		MailboxKey:     k.MailboxKey,
		OwnerChangeKey: k.OwnerChangeKey,
		PasskeyKey:     k.PasskeyKey,
	}, nil
}
