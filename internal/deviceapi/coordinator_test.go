package deviceapi

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/fount-labs/fount-mail-edge/internal/generation"
	"github.com/fount-labs/fount-mail-edge/internal/routing"
)

var nonceSeq atomic.Int64

func nextNonce() string { return "n" + strconv.FormatInt(nonceSeq.Add(1), 10) }

// genRequest signs a request the way a coordinator does: with Fount-Generation in
// the canonical string when gen isn't "".
func genRequest(t *testing.T, priv ed25519.PrivateKey, keyID, method, path string, body []byte, gen string) *http.Request {
	t.Helper()
	ts := time.Now()
	nonce := nextNonce()
	sum := sha256.Sum256(body)
	canonical := fmt.Sprintf("%s\n%s\n%s\n%d\n%s", method, strings.SplitN(path, "?", 2)[0], hex.EncodeToString(sum[:]), ts.Unix(), nonce)
	if gen != "" {
		canonical += "\n" + gen
	}
	req := httptest.NewRequest(method, path, strings.NewReader(string(body)))
	req.Header.Set("Fount-Key-Id", keyID)
	req.Header.Set("Fount-Timestamp", strconv.FormatInt(ts.Unix(), 10))
	req.Header.Set("Fount-Nonce", nonce)
	req.Header.Set("Fount-Signature", base64.StdEncoding.EncodeToString(ed25519.Sign(priv, []byte(canonical))))
	if gen != "" {
		req.Header.Set("Fount-Generation", gen)
	}
	return req
}

type coordinatorKey struct {
	gen  uint64
	priv ed25519.PrivateKey
	pub  ed25519.PublicKey
	id   string // Fount-Key-Id
	cert string
}

type coordFixture struct {
	t         *testing.T
	rt        *routing.Store
	blobs     *memBlobs
	api       *API
	authority ed25519.PrivateKey
	opts      Options
}

func newCoordFixture(t *testing.T) *coordFixture {
	t.Helper()
	rt, blobs := newRoutingStore(t)
	apub, apriv, _ := ed25519.GenerateKey(nil)
	f := &coordFixture{t: t, rt: rt, blobs: blobs, authority: apriv}
	f.opts = Options{
		Store:                newFakeMail(),
		Resolver:             NewKeyResolver(rt),
		Mutator:              rt,
		MailDomain:           "@fountbox.com",
		CoordinatorAuthority: apub,
	}
	f.api = New(f.opts)
	return f
}

// reboot is a new edge process on the same S3: routing loads from the object.
func (f *coordFixture) reboot() {
	f.t.Helper()
	rt, err := routing.New(context.Background(), f.blobs, []byte("test-routing-data-key"), []byte("test-mac-key"))
	if err != nil {
		f.t.Fatal(err)
	}
	f.rt = rt
	f.opts.Resolver, f.opts.Mutator = NewKeyResolver(rt), rt
	f.api = New(f.opts)
}

func (f *coordFixture) coordinator(gen uint64) coordinatorKey {
	f.t.Helper()
	pub, priv, _ := ed25519.GenerateKey(nil)
	cert, err := generation.Sign(f.authority, generation.Cert{Generation: gen, Key: pub, IssuedAt: time.Now().Unix()})
	if err != nil {
		f.t.Fatal(err)
	}
	return coordinatorKey{gen: gen, priv: priv, pub: pub, id: hex.EncodeToString(pub), cert: cert}
}

func (f *coordFixture) serve(req *http.Request) *httptest.ResponseRecorder {
	rec := httptest.NewRecorder()
	f.api.ServeHTTP(rec, req)
	return rec
}

func (f *coordFixture) enroll(mb mbox, c coordinatorKey) *httptest.ResponseRecorder {
	body, _ := json.Marshal(certificateRequest{Certificate: c.cert})
	return f.serve(genRequest(f.t, mb.sign, mb.idHex, "PUT", "/coordinator", body, ""))
}

func (f *coordFixture) claim(c coordinatorKey) *httptest.ResponseRecorder {
	body, _ := json.Marshal(certificateRequest{Certificate: c.cert})
	return f.serve(genRequest(f.t, c.priv, c.id, "POST", "/coordinator/generation", body, ""))
}

func (f *coordFixture) list(mb mbox, gen string) *httptest.ResponseRecorder {
	return f.serve(genRequest(f.t, mb.sign, mb.idHex, "GET", "/mail", nil, gen))
}

func wantCode(t *testing.T, rec *httptest.ResponseRecorder, status int, code string) {
	t.Helper()
	if rec.Code != status {
		t.Fatalf("status %d, want %d: %s", rec.Code, status, rec.Body)
	}
	if code == "" {
		return
	}
	var got struct{ Code string }
	_ = json.Unmarshal(rec.Body.Bytes(), &got)
	if got.Code != code {
		t.Fatalf("code %q, want %q: %s", got.Code, code, rec.Body)
	}
}

func TestEnrollFencesTheMailbox(t *testing.T) {
	f := newCoordFixture(t)
	mb := createMbox(t, f.rt, "ap@fountbox.com", "lic-1")
	other := createMbox(t, f.rt, "other@fountbox.com", "lic-2")
	c1 := f.coordinator(1)

	wantCode(t, f.list(mb, ""), http.StatusOK, "")
	wantCode(t, f.enroll(mb, c1), http.StatusOK, "")
	if !f.rt.Coordinated(mb.id) {
		t.Fatal("not enrolled")
	}
	// Enrolling again under the same generation is a no-op.
	wantCode(t, f.enroll(mb, c1), http.StatusOK, "")

	wantCode(t, f.list(mb, ""), http.StatusConflict, codeGenerationRequired)
	wantCode(t, f.list(mb, "1"), http.StatusOK, "")
	wantCode(t, f.list(mb, "2"), http.StatusConflict, codeUnknownGeneration)
	wantCode(t, f.list(mb, "x"), http.StatusUnauthorized, "")
	// A mailbox that isn't enrolled needs no generation.
	wantCode(t, f.list(other, ""), http.StatusOK, "")

	// The generation is covered by the signature: a header added afterwards
	// doesn't verify.
	req := genRequest(t, mb.sign, mb.idHex, "GET", "/mail", nil, "")
	req.Header.Set("Fount-Generation", "1")
	wantCode(t, f.serve(req), http.StatusUnauthorized, "")
}

// A newer generation, once it has spoken, refuses the old one on every enrolled
// mailbox and every coordinator route, and a reboot doesn't forget it.
func TestStaleGenerationRefused(t *testing.T) {
	f := newCoordFixture(t)
	mb := createMbox(t, f.rt, "ap@fountbox.com", "lic-1")
	c1, c2 := f.coordinator(1), f.coordinator(2)
	wantCode(t, f.enroll(mb, c1), http.StatusOK, "")

	wantCode(t, f.claim(c2), http.StatusOK, "")
	wantCode(t, f.list(mb, "1"), http.StatusConflict, codeStaleGeneration)
	wantCode(t, f.list(mb, "2"), http.StatusOK, "")
	wantCode(t, f.claim(c1), http.StatusConflict, codeStaleGeneration)
	wantCode(t, f.enroll(mb, c1), http.StatusConflict, codeStaleGeneration)
	// The same generation can't be claimed for another key.
	wantCode(t, f.claim(f.coordinator(2)), http.StatusConflict, codeGenerationConflict)

	f.reboot()
	wantCode(t, f.list(mb, "1"), http.StatusConflict, codeStaleGeneration)
	wantCode(t, f.claim(c1), http.StatusConflict, codeStaleGeneration)
	wantCode(t, f.list(mb, "2"), http.StatusOK, "")
	if gen, key, ok := f.rt.CurrentCoordinator(); !ok || gen != 2 || !key.Equal(c2.pub) {
		t.Fatalf("after reboot: %d %x %v", gen, key, ok)
	}

	// Enrolling under a newer generation moves the edge on too.
	c3 := f.coordinator(3)
	wantCode(t, f.enroll(mb, c3), http.StatusOK, "")
	wantCode(t, f.list(mb, "2"), http.StatusConflict, codeStaleGeneration)
}

func TestGenerationCertificateChecks(t *testing.T) {
	f := newCoordFixture(t)
	mb := createMbox(t, f.rt, "ap@fountbox.com", "lic-1")

	// A certificate from another authority.
	_, rogue, _ := ed25519.GenerateKey(nil)
	pub, priv, _ := ed25519.GenerateKey(nil)
	cert, _ := generation.Sign(rogue, generation.Cert{Generation: 9, Key: pub})
	forged := coordinatorKey{gen: 9, priv: priv, pub: pub, id: hex.EncodeToString(pub), cert: cert}
	wantCode(t, f.enroll(mb, forged), http.StatusForbidden, "")
	wantCode(t, f.claim(forged), http.StatusForbidden, "")

	// A real certificate claimed by a key it doesn't name.
	c := f.coordinator(1)
	stolen := c
	stolen.priv, _ = func() (ed25519.PrivateKey, error) { _, p, err := ed25519.GenerateKey(nil); return p, err }()
	stolen.id = hex.EncodeToString(stolen.priv.Public().(ed25519.PublicKey))
	wantCode(t, f.claim(stolen), http.StatusForbidden, "")

	// Enrollment is the mailbox's own call: another mailbox's key can't make it.
	other := createMbox(t, f.rt, "other@fountbox.com", "lic-2")
	body, _ := json.Marshal(certificateRequest{Certificate: c.cert})
	wantCode(t, f.serve(genRequest(t, other.sign, mb.idHex, "PUT", "/coordinator", body, "")), http.StatusUnauthorized, "")
	if f.rt.Coordinated(mb.id) {
		t.Fatal("enrolled by another mailbox's key")
	}
	if _, _, ok := f.rt.CurrentCoordinator(); ok {
		t.Fatal("a refused certificate moved the generation")
	}
}

// Without the authority key, the coordinator routes are stubs and nothing can be
// enrolled.
func TestCoordinatorRoutesOffWithoutAuthority(t *testing.T) {
	f := newCoordFixture(t)
	f.opts.CoordinatorAuthority = nil
	f.api = New(f.opts)
	mb := createMbox(t, f.rt, "ap@fountbox.com", "lic-1")
	wantCode(t, f.enroll(mb, f.coordinator(1)), http.StatusNotImplemented, "")
	wantCode(t, f.claim(f.coordinator(1)), http.StatusNotImplemented, "")
}

func (f *coordFixture) lapse(c coordinatorKey, mailboxHex string, body string) *httptest.ResponseRecorder {
	if body == "" {
		body = `{"mailbox_id":"` + mailboxHex + `","lapsed":true}`
	}
	return f.serve(genRequest(f.t, c.priv, c.id, "POST", "/coordinator/lapse", []byte(body), strconv.FormatUint(c.gen, 10)))
}

// The coordinator pauses an enrolled worker for lapse; only the current
// generation's key can, and GET /mail tells the broker.
func TestCoordinatorLapse(t *testing.T) {
	f := newCoordFixture(t)
	mb := createMbox(t, f.rt, "ap@fountbox.com", "lic-1")
	other := createMbox(t, f.rt, "other@fountbox.com", "lic-2")
	c1, c2 := f.coordinator(1), f.coordinator(2)

	// Not enrolled yet: refused.
	wantCode(t, f.claim(c1), http.StatusOK, "")
	wantCode(t, f.lapse(c1, mb.idHex, ""), http.StatusConflict, codeNotCoordinated)
	wantCode(t, f.enroll(mb, c1), http.StatusOK, "")

	rec := f.lapse(c1, mb.idHex, "")
	wantCode(t, rec, http.StatusOK, "")
	var out struct {
		MailboxID string `json:"mailbox_id"`
		Lapsed    bool   `json:"lapsed"`
		HoldUntil int64  `json:"hold_until"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil || !out.Lapsed || out.MailboxID != mb.idHex {
		t.Fatalf("body %s", rec.Body)
	}
	if l, _ := f.rt.Lapse(mb.id); !l {
		t.Fatal("not lapsed")
	}
	rec = f.list(mb, "1")
	wantCode(t, rec, http.StatusOK, "")
	if !strings.Contains(rec.Body.String(), `"lapsed":true`) {
		t.Fatalf("GET /mail: %s", rec.Body)
	}

	// The worker's own key can't lift it.
	body := []byte(`{"mailbox_id":"` + mb.idHex + `","lapsed":false}`)
	wantCode(t, f.serve(genRequest(t, mb.sign, mb.idHex, "POST", "/coordinator/lapse", body, "1")), http.StatusUnauthorized, "")

	// A stale generation can't touch it.
	wantCode(t, f.claim(c2), http.StatusOK, "")
	wantCode(t, f.lapse(c1, mb.idHex, `{"mailbox_id":"`+mb.idHex+`","lapsed":false}`), http.StatusConflict, codeStaleGeneration)
	wantCode(t, f.lapse(c2, other.idHex, ""), http.StatusConflict, codeNotCoordinated)
	wantCode(t, f.lapse(c2, mb.idHex, `{"mailbox_id":"`+mb.idHex+`"}`), http.StatusBadRequest, "")
	wantCode(t, f.lapse(c2, mb.idHex, `{"mailbox_id":"zz","lapsed":false}`), http.StatusBadRequest, "")

	f.reboot()
	if l, _ := f.rt.Lapse(mb.id); !l {
		t.Fatal("lapse lost in reboot")
	}
	wantCode(t, f.lapse(c2, mb.idHex, `{"mailbox_id":"`+mb.idHex+`","lapsed":false}`), http.StatusOK, "")
	if l, _ := f.rt.Lapse(mb.id); l {
		t.Fatal("still lapsed")
	}
}
