package link

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"slices"
	"sync/atomic"

	"github.com/fount-labs/fount-mail-edge/internal/send"
)

// The send link is mail-core's to mail-send, on their own closed network
// (docs/CONTAINER-SPLIT.md, stage 2). mail-send holds the send keyset; core
// holds the routing data, so core decides who may receive and send signs and
// delivers. Core is always the client.
//
//	POST /link/send         one message: its sender, its recipients, and the raw bytes
//	GET  /link/send/status  whether sending is on, and the held send keyset's commitment
//
// Like the front link, it's plain HTTP inside the enclave.

// SendStatus is what mail-send reports about sending, for core's /operator/status.
type SendStatus struct {
	State      string `json:"state"`                // "on", or "off: <why>"
	Commitment string `json:"commitment,omitempty"` // the held send keyset's, "" if none
}

type sendRequest struct {
	From       string   `json:"from"`
	Recipients []string `json:"recipients"`
	Message    []byte   `json:"message"`
}

type sendResponse struct {
	Results []send.Result `json:"results"`
}

type sendState struct {
	out    send.Transmitter
	status SendStatus
}

// SendServer is mail-send's side.
type SendServer struct {
	maxBytes int64
	state    atomic.Pointer[sendState]
}

// NewSendServer takes messages up to maxBytes. It answers that sending is off
// until Set gives it a Transmitter.
func NewSendServer(maxBytes int64) *SendServer {
	s := &SendServer{maxBytes: maxBytes}
	s.Set(nil, SendStatus{State: "off: starting"})
	return s
}

// Set reports st, and sends through out, or through nothing when out is nil.
func (s *SendServer) Set(out send.Transmitter, st SendStatus) {
	if out == nil && st.State == "on" {
		st.State = "off: no signer"
	}
	s.state.Store(&sendState{out: out, status: st})
}

func (s *SendServer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	switch {
	case r.Method == http.MethodPost && r.URL.Path == "/link/send":
		s.send(w, r)
	case r.Method == http.MethodGet && r.URL.Path == "/link/send/status":
		writeJSON(w, s.state.Load().status)
	default:
		http.NotFound(w, r)
	}
}

func (s *SendServer) send(w http.ResponseWriter, r *http.Request) {
	st := s.state.Load()
	if st.out == nil {
		http.Error(w, st.status.State, http.StatusServiceUnavailable)
		return
	}
	// The message rides base64 in JSON: a third more, plus the envelope.
	limit := s.maxBytes + s.maxBytes/3 + 4 + maxSmallBody
	var req sendRequest
	dec := json.NewDecoder(io.LimitReader(r.Body, limit))
	if err := dec.Decode(&req); err != nil || len(req.Message) == 0 || req.From == "" {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	if int64(len(req.Message)) > s.maxBytes {
		http.Error(w, "message too large", http.StatusRequestEntityTooLarge)
		return
	}
	res, err := st.out.Transmit(r.Context(), req.From, req.Recipients, req.Message)
	switch {
	case errors.Is(err, send.ErrBadMessage):
		http.Error(w, err.Error(), http.StatusBadRequest)
	case errors.Is(err, send.ErrNotOwner):
		http.Error(w, err.Error(), http.StatusForbidden)
	case errors.Is(err, send.ErrOff):
		http.Error(w, err.Error(), http.StatusServiceUnavailable)
	case err != nil:
		http.Error(w, "send failed", http.StatusBadGateway)
	default:
		writeJSON(w, sendResponse{Results: res})
	}
}

// SendClient is core's side. It is a send.Transmitter.
type SendClient struct {
	Base string // http://mail-send:7026
	HTTP *http.Client
}

var _ send.Transmitter = (*SendClient)(nil)

// Transmit hands one message to mail-send. send.ErrOff means mail-send has
// sending off; any error means nothing was sent.
func (c *SendClient) Transmit(ctx context.Context, from string, recipients []string, raw []byte) ([]send.Result, error) {
	body, err := json.Marshal(sendRequest{From: from, Recipients: recipients, Message: raw})
	if err != nil {
		return nil, err
	}
	resp, err := c.do(ctx, http.MethodPost, "/link/send", bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("mail-send: %w", err)
	}
	defer resp.Body.Close()
	msg := func() string {
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 400))
		return string(bytes.TrimSpace(b))
	}
	switch resp.StatusCode {
	case http.StatusOK:
	case http.StatusServiceUnavailable:
		return nil, fmt.Errorf("mail-send: %w (%s)", send.ErrOff, msg())
	case http.StatusBadRequest, http.StatusRequestEntityTooLarge:
		return nil, fmt.Errorf("%w: mail-send: %s", send.ErrBadMessage, msg())
	case http.StatusForbidden:
		return nil, send.ErrNotOwner
	default:
		return nil, fmt.Errorf("mail-send answered %s: %s", resp.Status, msg())
	}
	var out sendResponse
	if err := json.NewDecoder(io.LimitReader(resp.Body, maxSmallBody)).Decode(&out); err != nil {
		return nil, fmt.Errorf("mail-send results: %w", err)
	}
	// One result per recipient handed over, and none for anyone else. Results
	// are mail-send's report, not a decision, but they reach the device.
	if len(out.Results) != len(recipients) {
		return nil, fmt.Errorf("mail-send answered %d results for %d recipients", len(out.Results), len(recipients))
	}
	for _, r := range out.Results {
		if !slices.Contains(recipients, r.Recipient) {
			return nil, errors.New("mail-send answered for a recipient it wasn't given")
		}
	}
	return out.Results, nil
}

// Status asks mail-send whether sending is on.
func (c *SendClient) Status(ctx context.Context) (SendStatus, error) {
	resp, err := c.do(ctx, http.MethodGet, "/link/send/status", nil)
	if err != nil {
		return SendStatus{}, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return SendStatus{}, fmt.Errorf("mail-send status: %s", resp.Status)
	}
	var st SendStatus
	if err := json.NewDecoder(io.LimitReader(resp.Body, maxSmallBody)).Decode(&st); err != nil {
		return SendStatus{}, fmt.Errorf("mail-send status: %w", err)
	}
	if st.State == "" {
		return SendStatus{}, errors.New("mail-send status: empty")
	}
	return st, nil
}

func (c *SendClient) do(ctx context.Context, method, path string, body io.Reader) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, method, c.Base+path, body)
	if err != nil {
		return nil, err
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	client := c.HTTP
	if client == nil {
		client = http.DefaultClient
	}
	return client.Do(req)
}
