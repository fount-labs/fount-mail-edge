package link

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/fount-labs/fount-mail-edge/internal/send"
)

type fakeOut struct {
	from  string
	rcpts []string
	raw   []byte
	res   []send.Result
	err   error
}

func (f *fakeOut) Transmit(_ context.Context, from string, rcpts []string, raw []byte) ([]send.Result, error) {
	f.from, f.rcpts, f.raw = from, rcpts, raw
	if f.err != nil {
		return nil, f.err
	}
	if f.res != nil {
		return f.res, nil
	}
	out := make([]send.Result, len(rcpts))
	for i, r := range rcpts {
		out[i] = send.Result{Recipient: r, Status: send.Sent}
	}
	return out, nil
}

func sendRig(t *testing.T) (*SendServer, *SendClient) {
	t.Helper()
	srv := NewSendServer(1 << 10)
	ts := httptest.NewServer(srv)
	t.Cleanup(ts.Close)
	return srv, &SendClient{Base: ts.URL, HTTP: ts.Client()}
}

func TestSendLinkIsOffUntilSet(t *testing.T) {
	srv, c := sendRig(t)
	if _, err := c.Transmit(context.Background(), "w@fountbox.com", []string{"pat@x.com"}, []byte("m")); !errors.Is(err, send.ErrOff) {
		t.Fatalf("err = %v", err)
	}
	st, err := c.Status(context.Background())
	if err != nil || !strings.HasPrefix(st.State, "off: ") {
		t.Fatalf("%+v %v", st, err)
	}
	srv.Set(nil, SendStatus{State: "on"})
	if st, _ := c.Status(context.Background()); st.State == "on" {
		t.Fatal("on with no signer")
	}
}

func TestSendLinkCarriesTheMessage(t *testing.T) {
	srv, c := sendRig(t)
	out := &fakeOut{}
	srv.Set(out, SendStatus{State: "on", Commitment: "abc"})
	raw := []byte("From: w@fountbox.com\r\n\r\n\x00binary\xff")
	res, err := c.Transmit(context.Background(), "w@fountbox.com", []string{"pat@x.com", "jo@y.com"}, raw)
	if err != nil || len(res) != 2 || res[1].Recipient != "jo@y.com" {
		t.Fatalf("%+v %v", res, err)
	}
	if out.from != "w@fountbox.com" || len(out.rcpts) != 2 || string(out.raw) != string(raw) {
		t.Fatalf("mail-send got %q %v %q", out.from, out.rcpts, out.raw)
	}
	st, err := c.Status(context.Background())
	if err != nil || st != (SendStatus{State: "on", Commitment: "abc"}) {
		t.Fatalf("%+v %v", st, err)
	}
}

func TestSendLinkErrors(t *testing.T) {
	for name, c := range map[string]struct {
		err  error
		want error
	}{
		"bad message": {send.ErrBadMessage, send.ErrBadMessage},
		"not owner":   {send.ErrNotOwner, send.ErrNotOwner},
		"off":         {send.ErrOff, send.ErrOff},
	} {
		srv, cl := sendRig(t)
		srv.Set(&fakeOut{err: c.err}, SendStatus{State: "on"})
		if _, err := cl.Transmit(context.Background(), "w@fountbox.com", []string{"pat@x.com"}, []byte("m")); !errors.Is(err, c.want) {
			t.Errorf("%s: err = %v", name, err)
		}
	}
	srv, cl := sendRig(t)
	srv.Set(&fakeOut{err: errors.New("relay down")}, SendStatus{State: "on"})
	if _, err := cl.Transmit(context.Background(), "w@fountbox.com", []string{"pat@x.com"}, []byte("m")); err == nil || errors.Is(err, send.ErrOff) {
		t.Errorf("relay down: err = %v", err)
	}
	if _, err := cl.Transmit(context.Background(), "w@fountbox.com", []string{"pat@x.com"}, make([]byte, 2<<10)); !errors.Is(err, send.ErrBadMessage) {
		t.Errorf("too large: err = %v", err)
	}
}

// Core passes on only results for the recipients it handed over.
func TestSendLinkChecksTheResults(t *testing.T) {
	for name, res := range map[string][]send.Result{
		"too few":  {{Recipient: "pat@x.com", Status: send.Sent}},
		"stranger": {{Recipient: "pat@x.com", Status: send.Sent}, {Recipient: "stranger@z.com", Status: send.Sent}},
	} {
		srv, c := sendRig(t)
		srv.Set(&fakeOut{res: res}, SendStatus{State: "on"})
		if _, err := c.Transmit(context.Background(), "w@fountbox.com", []string{"pat@x.com", "jo@y.com"}, []byte("m")); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestSendLinkServesNothingElse(t *testing.T) {
	srv, _ := sendRig(t)
	for _, r := range []*http.Request{
		httptest.NewRequest(http.MethodGet, "/link/send", nil),
		httptest.NewRequest(http.MethodPost, "/link/put", nil),
		httptest.NewRequest(http.MethodGet, "/.well-known/acme-challenge/x", nil),
	} {
		rec := httptest.NewRecorder()
		srv.ServeHTTP(rec, r)
		if rec.Code != http.StatusNotFound {
			t.Errorf("%s %s: %d", r.Method, r.URL.Path, rec.Code)
		}
	}
}
