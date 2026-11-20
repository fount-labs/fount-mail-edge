package deviceapi

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"testing"
)

// addChild adds a worker under mb's handle and returns it with its keys.
func addChild(t *testing.T, f *coordFixture, mb mbox, address string) mbox {
	t.Helper()
	_, sign, _ := ed25519.GenerateKey(rand.Reader)
	_, owner, _ := ed25519.GenerateKey(rand.Reader)
	dec := make([]byte, 32)
	_, _ = rand.Read(dec)
	_, pass := testCredential(t)
	req := addressRequest{Address: address, DecryptionKey: dec, SigningKey: sign.Public().(ed25519.PublicKey), OwnerChangeKey: owner.Public().(ed25519.PublicKey), PasskeyKey: pass}
	req.KeyChainSig = ed25519.Sign(mb.mailbox, keyChain(req.DecryptionKey, req.SigningKey, req.OwnerChangeKey, req.PasskeyKey))
	body, _ := json.Marshal(req)
	rec := f.serve(genRequest(t, mb.mailbox, mb.idHex, "POST", "/address", body, ""))
	wantCode(t, rec, http.StatusCreated, "")
	var out struct {
		MailboxID string `json:"mailbox_id"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &out)
	id, _ := hex.DecodeString(out.MailboxID)
	return mbox{id: id, idHex: out.MailboxID, sign: sign, mailbox: mb.mailbox, owner: owner}
}

func removeBody(idHex string) []byte {
	b, _ := json.Marshal(removeRequest{MailboxID: idHex})
	return b
}

func TestMailboxKeyRemovesAWorker(t *testing.T) {
	f, mb, _ := custodyFixture(t)
	child := addChild(t, f, mb, "ap.worker@fountbox.com")
	remove := func(priv ed25519.PrivateKey, keyID, target string) *http.Request {
		return genRequest(t, priv, keyID, "POST", "/address/remove", removeBody(target), "")
	}

	// Not with the worker's own address key, nor another handle's mailbox key.
	wantCode(t, f.serve(remove(child.sign, child.idHex, child.idHex)), http.StatusUnauthorized, "")
	other := createMbox(t, f.rt, "other@fountbox.com", "lic-2")
	wantCode(t, f.serve(remove(other.mailbox, other.idHex, child.idHex)), http.StatusNotFound, "")

	wantCode(t, f.serve(remove(mb.mailbox, mb.idHex, child.idHex)), http.StatusOK, "")
	if _, ok := f.rt.Snapshot(child.id); ok {
		t.Fatal("still live")
	}
	// Retried, signed under the removed id itself: still 200.
	wantCode(t, f.serve(remove(mb.mailbox, child.idHex, child.idHex)), http.StatusOK, "")
	wantCode(t, f.serve(remove(mb.mailbox, mb.idHex, child.idHex)), http.StatusOK, "")
	// The removed id's key id gives the mailbox key nothing else.
	again, _ := json.Marshal(childBody(t, "ar.worker@fountbox.com", mb.mailbox))
	wantCode(t, f.serve(genRequest(t, mb.mailbox, child.idHex, "POST", "/address", again, "")), http.StatusNotFound, "")
	// The worker's address key is gone with it.
	wantCode(t, f.serve(genRequest(t, child.sign, child.idHex, "GET", "/mail", nil, "")), http.StatusUnauthorized, "")
	// Named again inside the quarantine: refused.
	reuse, _ := json.Marshal(childBody(t, "ap.worker@fountbox.com", mb.mailbox))
	wantCode(t, f.serve(genRequest(t, mb.mailbox, mb.idHex, "POST", "/address", reuse, "")), http.StatusConflict, "")

	// The handle's own address isn't removed.
	wantCode(t, f.serve(remove(mb.mailbox, mb.idHex, mb.idHex)), http.StatusConflict, codeHandle)
}

func TestOnlyTheCoordinatorRemovesAnEnrolledWorker(t *testing.T) {
	f, mb, c1 := custodyFixture(t)
	child := addChild(t, f, mb, "ap.worker@fountbox.com")
	device := addChild(t, f, mb, "dv.worker@fountbox.com")
	wantCode(t, f.enroll(child, c1), http.StatusOK, "")

	wantCode(t, f.serve(genRequest(t, mb.mailbox, mb.idHex, "POST", "/address/remove", removeBody(child.idHex), "")), http.StatusConflict, codeCoordinatorOnly)
	byCoord := func(target string) *http.Request {
		return genRequest(t, c1.priv, c1.id, "POST", "/coordinator/remove", removeBody(target), "1")
	}
	wantCode(t, f.serve(genRequest(t, child.sign, child.idHex, "POST", "/coordinator/remove", removeBody(child.idHex), "1")), http.StatusUnauthorized, "")
	wantCode(t, f.serve(byCoord(device.idHex)), http.StatusConflict, codeNotCoordinated)

	wantCode(t, f.serve(byCoord(child.idHex)), http.StatusOK, "")
	if _, ok := f.rt.Snapshot(child.id); ok {
		t.Fatal("still live")
	}
	wantCode(t, f.serve(byCoord(child.idHex)), http.StatusOK, "")

	// A stale coordinator can't.
	c2 := f.coordinator(2)
	wantCode(t, f.claim(c2), http.StatusOK, "")
	wantCode(t, f.serve(byCoord(device.idHex)), http.StatusConflict, codeStaleGeneration)

	// An enrolled handle stays.
	wantCode(t, f.enroll(mb, c2), http.StatusOK, "")
	wantCode(t, f.serve(genRequest(t, c2.priv, c2.id, "POST", "/coordinator/remove", removeBody(mb.idHex), "2")), http.StatusConflict, codeHandle)
}
