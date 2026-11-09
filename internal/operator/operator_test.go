package operator

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/fount-labs/fount-mail-edge/internal/routing"
	"github.com/fount-labs/fount-mail-edge/internal/smtp"
	"github.com/fount-labs/fount-mail-edge/internal/store"
	"github.com/fount-labs/fount-mail-vault/wire"
)

type memBlobs struct {
	mu      sync.Mutex
	objs    map[string][]byte
	failGet bool
}

func newMemBlobs() *memBlobs { return &memBlobs{objs: map[string][]byte{}} }

func (b *memBlobs) Put(_ context.Context, key string, data []byte) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.objs[key] = append([]byte(nil), data...)
	return nil
}

func (b *memBlobs) Get(_ context.Context, key string) ([]byte, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.failGet {
		return nil, errors.New("s3 down")
	}
	v, ok := b.objs[key]
	if !ok {
		return nil, store.ErrNotFound
	}
	return append([]byte(nil), v...), nil
}

func (b *memBlobs) List(context.Context, string) ([]store.Object, error) { return nil, nil }

func (b *memBlobs) Delete(_ context.Context, key string) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	delete(b.objs, key)
	return nil
}

func (b *memBlobs) GetVersioned(ctx context.Context, k string) ([]byte, string, error) {
	v, err := b.Get(ctx, k)
	if err != nil {
		return nil, "", err
	}
	return v, etagOf(v), nil
}

func (b *memBlobs) PutIfMatch(_ context.Context, k string, d []byte, etag string) (string, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	cur, ok := b.objs[k]
	if ok && etag != etagOf(cur) || !ok && etag != "" {
		return "", store.ErrConflict
	}
	b.objs[k] = append([]byte(nil), d...)
	return etagOf(d), nil
}

func etagOf(d []byte) string {
	h := sha256.Sum256(d)
	return hex.EncodeToString(h[:])
}

type fixture struct {
	t        *testing.T
	blobs    *memBlobs
	backups  *memBlobs
	rk, mk   []byte
	opKey    ed25519.PrivateKey
	routing  *Routing
	handler  *Handler
	client   *Client
	srv      *httptest.Server
	loaded   chan *routing.Store
	loadErr  chan error
	drained  atomic.Bool
	bootSign ed25519.PrivateKey
	bootID   []byte
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	_, bootSign, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	f := &fixture{
		t: t, blobs: newMemBlobs(), backups: newMemBlobs(),
		rk: bytes.Repeat([]byte{1}, 32), mk: bytes.Repeat([]byte{2}, 32),
		opKey: priv, routing: NewRouting(),
		loaded: make(chan *routing.Store, 1), loadErr: make(chan error, 1),
		bootSign: bootSign, bootID: bytes.Repeat([]byte{9}, 16),
	}
	f.handler = NewHandler(pub, f.routing)
	f.srv = httptest.NewServer(f.handler)
	t.Cleanup(f.srv.Close)
	f.client = &Client{HTTP: f.srv.Client(), Base: f.srv.URL, Key: priv}
	return f
}

func (f *fixture) open(ctx context.Context) (*routing.Store, error) {
	return routing.New(ctx, f.blobs, f.rk, f.mk, routing.WithBackup(f.backups, f.bootSign, f.bootID))
}

// boot runs Load in the background, as the edge does, and waits for it to settle.
func (f *fixture) boot(want State) {
	f.t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	f.t.Cleanup(cancel)
	go func() {
		s, err := f.routing.Load(ctx, Backend{Blobs: f.blobs, RoutingDataKey: f.rk, MailDomain: "@fountbox.com"}, f.open)
		if err != nil {
			f.loadErr <- err
			return
		}
		f.loaded <- s
	}()
	if want == StateServing {
		f.serve(f.waitLoaded())
		return
	}
	f.waitState(want)
}

func (f *fixture) serve(s *routing.Store) {
	f.routing.Serve(s, nil, func(context.Context) { f.drained.Store(true) })
}

func (f *fixture) waitState(want State) {
	f.t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for f.routing.State() != want {
		if time.Now().After(deadline) {
			f.t.Fatalf("state = %s, want %s", f.routing.State(), want)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func (f *fixture) waitLoaded() *routing.Store {
	f.t.Helper()
	select {
	case s := <-f.loaded:
		return s
	case err := <-f.loadErr:
		f.t.Fatalf("Load: %v", err)
	case <-time.After(5 * time.Second):
		f.t.Fatal("Load didn't return")
	}
	return nil
}

func (f *fixture) do(op string, payload any) (map[string]any, error) {
	var out map[string]any
	err := f.client.Do(context.Background(), op, payload, &out)
	return out, err
}

// send posts a hand-made request, for the cases the client can't produce.
func (f *fixture) send(op string, req Request) int {
	f.t.Helper()
	raw, _ := json.Marshal(req)
	resp, err := http.Post(f.srv.URL+"/operator/"+op, "application/json", bytes.NewReader(raw))
	if err != nil {
		f.t.Fatal(err)
	}
	resp.Body.Close()
	return resp.StatusCode
}

func (f *fixture) nonce() string {
	f.t.Helper()
	var b BeginResponse
	if err := wire.PostJSON(context.Background(), f.srv.Client(), f.srv.URL+"/operator/begin", struct{}{}, &b); err != nil {
		f.t.Fatal(err)
	}
	return b.Nonce
}

func (f *fixture) signed(op, nonce string, payload []byte) Request {
	return Request{Nonce: nonce, Payload: payload, Signature: ed25519.Sign(f.opKey, Message(op, nonce, payload))}
}

func roleKeys(t *testing.T) PublicKeys {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	key := func(b byte) []byte { return bytes.Repeat([]byte{b}, 32) }
	return PublicKeys{
		DecryptionKey: key(1), SigningKey: key(2), MailboxKey: key(3), OwnerChangeKey: key(4),
		PasskeyKey: append([]byte{0x04}, append(priv.X.FillBytes(make([]byte, 32)), priv.Y.FillBytes(make([]byte, 32))...)...),
	}
}

// backup makes a real signed backup holding one role mailbox, records its boot,
// and returns it. The live object is left as it is.
func (f *fixture) backup() []byte {
	f.t.Helper()
	ctx := context.Background()
	scratch := newMemBlobs()
	if err := routing.Initialize(ctx, scratch, f.rk); err != nil {
		f.t.Fatal(err)
	}
	s, err := routing.New(ctx, scratch, f.rk, f.mk, routing.WithBackup(f.backups, f.bootSign, f.bootID))
	if err != nil {
		f.t.Fatal(err)
	}
	m, err := NewMailbox("postmaster", "@fountbox.com", roleKeys(f.t))
	if err != nil {
		f.t.Fatal(err)
	}
	if _, err := s.Create(ctx, m); err != nil {
		f.t.Fatal(err)
	}
	f.recordBoot(f.bootSign.Public().(ed25519.PublicKey))
	b, err := f.backups.Get(ctx, "routing/current")
	if err != nil {
		f.t.Fatal(err)
	}
	return b
}

func (f *fixture) recordBoot(pub ed25519.PublicKey) {
	f.t.Helper()
	raw, _ := json.Marshal(store.Boot{BootID: hex.EncodeToString(f.bootID), SigningKey: pub})
	_ = f.blobs.Put(context.Background(), "edge/boots/"+hex.EncodeToString(f.bootID), raw)
}

func accepting(t *testing.T, s *routing.Store, addr string) bool {
	t.Helper()
	st, err := s.Status(context.Background(), addr)
	if err != nil {
		t.Fatal(err)
	}
	return st == smtp.RecipientAccepting
}

func TestInitWritesTheFirstObjectAndBootContinues(t *testing.T) {
	f := newFixture(t)
	f.boot(StateNoObject)
	if _, err := f.do(OpInit, struct{}{}); err != nil {
		t.Fatal(err)
	}
	f.waitLoaded()
	if _, err := f.blobs.Get(context.Background(), routing.ObjectKey); err != nil {
		t.Fatalf("no object after init: %v", err)
	}
}

func TestInitNeverReplacesAnObject(t *testing.T) {
	f := newFixture(t)
	if err := routing.Initialize(context.Background(), f.blobs, f.rk); err != nil {
		t.Fatal(err)
	}
	f.boot(StateServing)
	before, _ := f.blobs.Get(context.Background(), routing.ObjectKey)
	if _, err := f.do(OpInit, struct{}{}); err == nil || !strings.Contains(err.Error(), "409") {
		t.Fatalf("init on a serving edge: %v", err)
	}
	after, _ := f.blobs.Get(context.Background(), routing.ObjectKey)
	if !bytes.Equal(before, after) {
		t.Fatal("init changed an existing object")
	}
}

func TestOperationsWaitForTheKeys(t *testing.T) {
	f := newFixture(t)
	for op, payload := range map[string]any{OpInit: struct{}{}, OpRestore: RestorePayload{Backup: []byte("x")}} {
		if _, err := f.do(op, payload); err == nil || !strings.Contains(err.Error(), "503") {
			t.Errorf("%s before the keys: %v", op, err)
		}
	}
}

func TestLoadReturnsOtherErrors(t *testing.T) {
	f := newFixture(t)
	f.blobs.failGet = true
	f.boot(StateNoKeys)
	select {
	case err := <-f.loadErr:
		if errors.Is(err, routing.ErrNoObject) {
			t.Fatalf("an S3 failure was taken for a missing object: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("an S3 failure left the edge waiting for an operator")
	}
}

func TestSignatureIsRequired(t *testing.T) {
	f := newFixture(t)
	f.boot(StateNoObject)
	_, stranger, _ := ed25519.GenerateKey(rand.Reader)
	n := f.nonce()
	forged := Request{Nonce: n, Payload: []byte("{}"), Signature: ed25519.Sign(stranger, Message(OpInit, n, []byte("{}")))}
	if code := f.send(OpInit, forged); code != http.StatusForbidden {
		t.Fatalf("a stranger's signature: %d", code)
	}
	if code := f.send(OpInit, Request{Nonce: n, Payload: []byte("{}")}); code != http.StatusForbidden {
		t.Fatalf("no signature: %d", code)
	}
	// Refused requests don't spend the nonce, so a stranger can't burn them.
	if code := f.send(OpInit, f.signed(OpInit, n, []byte("{}"))); code != http.StatusOK {
		t.Fatalf("the operator's request after refusals: %d", code)
	}
	f.waitLoaded()
}

func TestSignatureBindsOperationAndPayload(t *testing.T) {
	f := newFixture(t)
	f.boot(StateNoObject)
	n := f.nonce()
	if code := f.send(OpRestore, f.signed(OpInit, n, []byte("{}"))); code != http.StatusForbidden {
		t.Fatalf("an init signature sent as a restore: %d", code)
	}
	req := f.signed(OpRestore, n, []byte(`{"write":false}`))
	req.Payload = []byte(`{"write":true}`)
	if code := f.send(OpRestore, req); code != http.StatusForbidden {
		t.Fatalf("a changed payload: %d", code)
	}
}

func TestNonceIsOneUseAndExpires(t *testing.T) {
	f := newFixture(t)
	f.boot(StateNoObject)
	n := f.nonce()
	if code := f.send(OpInit, f.signed(OpInit, n, []byte("{}"))); code != http.StatusOK {
		t.Fatalf("first use: %d", code)
	}
	f.waitLoaded()
	if code := f.send(OpInit, f.signed(OpInit, n, []byte("{}"))); code != http.StatusForbidden {
		t.Fatalf("replay: %d", code)
	}
	if code := f.send(OpInit, f.signed(OpInit, "made-up", []byte("{}"))); code != http.StatusForbidden {
		t.Fatalf("a nonce the edge never issued: %d", code)
	}

	old := f.nonce()
	f.handler.now = func() time.Time { return time.Now().Add(nonceTTL + time.Second) }
	if code := f.send(OpInit, f.signed(OpInit, old, []byte("{}"))); code != http.StatusForbidden {
		t.Fatalf("an expired nonce: %d", code)
	}
}

func TestOutstandingNoncesAreBounded(t *testing.T) {
	f := newFixture(t)
	for range maxNonces {
		f.nonce()
	}
	var b BeginResponse
	if err := wire.PostJSON(context.Background(), f.srv.Client(), f.srv.URL+"/operator/begin", struct{}{}, &b); err == nil || !strings.Contains(err.Error(), "429") {
		t.Fatalf("nonce past the limit: %v", err)
	}
	f.handler.now = func() time.Time { return time.Now().Add(nonceTTL + time.Second) }
	f.nonce() // expired ones are cleared
}

func TestProvisionAddsARoleMailboxAtOnce(t *testing.T) {
	f := newFixture(t)
	if err := routing.Initialize(context.Background(), f.blobs, f.rk); err != nil {
		t.Fatal(err)
	}
	f.boot(StateNoKeys)
	s := f.waitLoaded()
	f.serve(s)
	out, err := f.do(OpProvision, ProvisionPayload{Role: "abuse", Keys: roleKeys(t)})
	if err != nil {
		t.Fatal(err)
	}
	if out["mailbox_id"] != hex.EncodeToString(s.MailboxID("abuse@fountbox.com")) {
		t.Fatalf("mailbox id = %v", out["mailbox_id"])
	}
	if !accepting(t, s, "abuse@fountbox.com") {
		t.Fatal("the running edge doesn't accept mail for the new mailbox")
	}
	if _, err := f.do(OpProvision, ProvisionPayload{Role: "abuse", Keys: roleKeys(t)}); err == nil || !strings.Contains(err.Error(), "409") {
		t.Fatalf("a second abuse@: %v", err)
	}
}

func TestProvisionOnlyRoleAddresses(t *testing.T) {
	f := newFixture(t)
	if err := routing.Initialize(context.Background(), f.blobs, f.rk); err != nil {
		t.Fatal(err)
	}
	f.boot(StateServing)
	if _, err := f.do(OpProvision, ProvisionPayload{Role: "admin", Keys: roleKeys(t)}); err == nil || !strings.Contains(err.Error(), "400") {
		t.Fatalf("admin@: %v", err)
	}
}

func TestProvisionNeedsAServingEdge(t *testing.T) {
	f := newFixture(t)
	f.boot(StateNoObject)
	if _, err := f.do(OpProvision, ProvisionPayload{Role: "abuse", Keys: roleKeys(t)}); err == nil || !strings.Contains(err.Error(), "409") {
		t.Fatalf("provision with no object: %v", err)
	}
}

func TestNewMailbox(t *testing.T) {
	m, err := NewMailbox("abuse", "fountbox.com", roleKeys(t))
	if err != nil {
		t.Fatal(err)
	}
	if m.Address != "abuse@fountbox.com" || m.EntitlementExp != 0 || len(m.LicenseHash) != 0 {
		t.Fatalf("mailbox = %+v", m)
	}
	for _, role := range []string{"", "admin", "support", "worker", "abuse@fountbox.com"} {
		if _, err := NewMailbox(role, "@fountbox.com", roleKeys(t)); err == nil {
			t.Errorf("role %q accepted", role)
		}
	}
	for name, change := range map[string]func(*PublicKeys){
		"decryption": func(k *PublicKeys) { k.DecryptionKey = nil },
		"signing":    func(k *PublicKeys) { k.SigningKey = []byte{1} },
		"mailbox":    func(k *PublicKeys) { k.MailboxKey = nil },
		"owner":      func(k *PublicKeys) { k.OwnerChangeKey = nil },
		"passkey":    func(k *PublicKeys) { k.PasskeyKey = []byte{4} },
	} {
		k := roleKeys(t)
		change(&k)
		if _, err := NewMailbox("abuse", "@fountbox.com", k); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestRestoreIntoAnEmptyDeployment(t *testing.T) {
	f := newFixture(t)
	backup := f.backup()
	f.boot(StateNoObject)

	out, err := f.do(OpRestore, RestorePayload{Backup: backup})
	if err != nil {
		t.Fatal(err)
	}
	if out["written"] != false || out["mailboxes"] != float64(1) {
		t.Fatalf("verify only = %v", out)
	}
	if _, err := f.blobs.Get(context.Background(), routing.ObjectKey); !errors.Is(err, store.ErrNotFound) {
		t.Fatal("a restore without write wrote")
	}

	if _, err := f.do(OpRestore, RestorePayload{Backup: backup, Write: true, SkipSequences: 100}); err != nil {
		t.Fatal(err)
	}
	s := f.waitLoaded()
	if !accepting(t, s, "postmaster@fountbox.com") {
		t.Fatal("the restored mailbox isn't there")
	}
	seq, err := s.NextSequence(context.Background(), s.MailboxID("postmaster@fountbox.com"))
	if err != nil || seq <= 100 {
		t.Fatalf("next sequence = %d, %v; want past the skip", seq, err)
	}
}

func TestRestoreRefusesABackupTheBootDidntSign(t *testing.T) {
	f := newFixture(t)
	backup := f.backup()
	other, _, _ := ed25519.GenerateKey(rand.Reader)
	f.recordBoot(other)
	f.boot(StateNoObject)
	if _, err := f.do(OpRestore, RestorePayload{Backup: backup, Write: true}); err == nil || !strings.Contains(err.Error(), "400") {
		t.Fatalf("a backup the recorded boot didn't sign: %v", err)
	}
	// A record for another boot is refused, even with the right key.
	wrong, _ := json.Marshal(store.Boot{BootID: strings.Repeat("ab", 16), SigningKey: f.bootSign.Public().(ed25519.PublicKey)})
	if _, err := f.do(OpRestore, RestorePayload{Backup: backup, BootRecord: wrong}); err == nil || !strings.Contains(err.Error(), "400") {
		t.Fatalf("another boot's record: %v", err)
	}
	// The operator's copy of the boot record is used when it's sent.
	raw, _ := json.Marshal(store.Boot{BootID: hex.EncodeToString(f.bootID), SigningKey: f.bootSign.Public().(ed25519.PublicKey)})
	if _, err := f.do(OpRestore, RestorePayload{Backup: backup, BootRecord: raw}); err != nil {
		t.Fatalf("with the right boot record: %v", err)
	}
}

func TestRestoreOverAServingEdgeDrainsAndRestarts(t *testing.T) {
	f := newFixture(t)
	backup := f.backup()
	if err := routing.Initialize(context.Background(), f.blobs, f.rk); err != nil {
		t.Fatal(err)
	}
	f.boot(StateServing)

	if _, err := f.do(OpRestore, RestorePayload{Backup: backup, Write: true}); err == nil || !strings.Contains(err.Error(), "409") {
		t.Fatalf("a restore without replace: %v", err)
	}
	if f.drained.Load() {
		t.Fatal("a refused restore stopped mail")
	}
	select {
	case <-f.routing.Restart():
		t.Fatal("a refused restore restarted the edge")
	default:
	}

	out, err := f.do(OpRestore, RestorePayload{Backup: backup, Write: true, Replace: true})
	if err != nil {
		t.Fatal(err)
	}
	if out["written"] != true || out["restarting"] != true || !f.drained.Load() {
		t.Fatalf("restore = %v, drained %v", out, f.drained.Load())
	}
	select {
	case <-f.routing.Restart():
	case <-time.After(time.Second):
		t.Fatal("the edge didn't restart after a restore")
	}
	if _, err := f.do(OpProvision, ProvisionPayload{Role: "abuse", Keys: roleKeys(t)}); err == nil || !strings.Contains(err.Error(), "409") {
		t.Fatalf("provision while restarting: %v", err)
	}
	fresh, err := f.open(context.Background())
	if err != nil || !accepting(t, fresh, "postmaster@fountbox.com") {
		t.Fatalf("the next boot doesn't see the restored object: %v", err)
	}
}

func TestAnUnreadableObjectWaitsForAReplace(t *testing.T) {
	f := newFixture(t)
	backup := f.backup()
	_ = f.blobs.Put(context.Background(), routing.ObjectKey, []byte("garbage that won't decrypt"))
	f.boot(StateCorrupt)

	if _, err := f.do(OpInit, struct{}{}); err == nil || !strings.Contains(err.Error(), "409") {
		t.Fatalf("init over an unreadable object: %v", err)
	}
	if _, err := f.do(OpRestore, RestorePayload{Backup: backup, Write: true}); err == nil || !strings.Contains(err.Error(), "409") {
		t.Fatalf("restore without replace: %v", err)
	}
	if _, err := f.do(OpRestore, RestorePayload{Backup: backup, Write: true, Replace: true}); err != nil {
		t.Fatal(err)
	}
	if s := f.waitLoaded(); !accepting(t, s, "postmaster@fountbox.com") {
		t.Fatal("the restored mailbox isn't there")
	}
	if f.drained.Load() {
		t.Fatal("drained an edge that wasn't serving")
	}
}

func TestStatusNeedsNoSignature(t *testing.T) {
	f := newFixture(t)
	f.boot(StateNoObject)
	got, err := f.client.Status(context.Background())
	if err != nil || got.Routing != StateNoObject {
		t.Fatalf("status = %+v, %v", got, err)
	}
}

// CAA `accounturi` pins the ACME account, and Tinfoil has no container logs, so
// the URL is published on the unauthenticated status route once it's known.
func TestStatusPublishesACMEAccountOnceKnown(t *testing.T) {
	f := newFixture(t)
	var url atomic.Pointer[string]
	f.handler.SetACMEAccount(func() string {
		if u := url.Load(); u != nil {
			return *u
		}
		return ""
	})
	f.boot(StateNoObject)

	resp, err := http.Get(f.srv.URL + "/operator/status")
	if err != nil {
		t.Fatal(err)
	}
	var raw map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&raw); err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if _, ok := raw["acme_account"]; ok {
		t.Fatalf("acme_account present before registration: %v", raw)
	}

	want := "https://acme-v02.api.letsencrypt.org/acme/acct/123456"
	url.Store(&want)
	got, err := (&Client{HTTP: f.srv.Client(), Base: f.srv.URL}).Status(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if got.ACMEAccount != want || got.Routing != StateNoObject {
		t.Fatalf("status = %+v, want account %s", got, want)
	}
}
