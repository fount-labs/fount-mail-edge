package sendercheck

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"os"
	"os/exec"
	"regexp"
	"sync"
	"time"
)

// Subcommand is the edge's argument that runs Serve: `/edge sender-check`.
const Subcommand = "sender-check"

// The edge and its child speak length-prefixed frames (4-byte big-endian length,
// then the bytes) over the child's stdin and stdout:
//
//	edge  -> child  {"recipient":…,"received_at":ms}, then the raw message
//	child -> edge   {"names":[…]}, the key records it needs (KeyNames), or {"error":…}
//	edge  -> child  {"answers":{name:{"txt":[…]} or {"status":"nxdomain"|"temperror"}}}
//	child -> edge   {"verdict":{…}} or {"error":…}
//
// The edge validates every name before asking DNS, and checks the verdict's shape
// before storing it.

const (
	// Timeout covers starting the child, every DNS answer and the verdict.
	Timeout = 20 * time.Second
	// maxRequest bounds a frame the child reads: the message itself, which the
	// edge already limits.
	maxRequest = 64 << 20
	maxReply   = MaxBytes + 4096
	maxStderr  = 4 << 10
	// maxChildren bounds checks running at once. Each holds a message in memory.
	maxChildren = 16
)

type request struct {
	Recipient  string `json:"recipient"`
	ReceivedAt int64  `json:"received_at"`
}

type answer struct {
	TXT    []string `json:"txt,omitempty"`
	Status string   `json:"status,omitempty"` // "", "nxdomain" or "temperror"
}

type answers struct {
	Answers map[string]answer `json:"answers"`
}

type reply struct {
	Names   []string        `json:"names,omitempty"`
	Verdict json.RawMessage `json:"verdict,omitempty"`
	Error   string          `json:"error,omitempty"`
}

func writeFrame(w io.Writer, b []byte) error {
	var n [4]byte
	binary.BigEndian.PutUint32(n[:], uint32(len(b)))
	if _, err := w.Write(n[:]); err != nil {
		return err
	}
	_, err := w.Write(b)
	return err
}

func readFrame(r io.Reader, max int) ([]byte, error) {
	var n [4]byte
	if _, err := io.ReadFull(r, n[:]); err != nil {
		return nil, err
	}
	size := binary.BigEndian.Uint32(n[:])
	if int64(size) > int64(max) {
		return nil, fmt.Errorf("frame of %d bytes is over the limit", size)
	}
	b := make([]byte, size)
	_, err := io.ReadFull(r, b)
	return b, err
}

func decodeStrict(b []byte, v any) error {
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		return err
	}
	if dec.More() {
		return errors.New("trailing data")
	}
	return nil
}

func writeJSON(w io.Writer, v any) error {
	b, err := json.Marshal(v)
	if err != nil {
		return err
	}
	return writeFrame(w, b)
}

// Serve is the child: it reads one message, asks for the key records it needs,
// and writes the verdict. It holds no keys and makes no network calls.
func Serve(r io.Reader, w io.Writer) error {
	head, err := readFrame(r, 4096)
	if err != nil {
		return err
	}
	var req request
	if err := decodeStrict(head, &req); err != nil {
		return err
	}
	raw, err := readFrame(r, maxRequest)
	if err != nil {
		return err
	}
	names, err := KeyNames(raw)
	if err != nil {
		return writeJSON(w, reply{Error: errUnreadable})
	}
	if names == nil {
		names = []string{}
	}
	if err := writeJSON(w, map[string][]string{"names": names}); err != nil {
		return err
	}
	b, err := readFrame(r, maxReply)
	if err != nil {
		return err
	}
	var ans answers
	if err := decodeStrict(b, &ans); err != nil {
		return err
	}
	lookup := func(name string) ([]string, error) {
		a, ok := ans.Answers[name]
		switch {
		case !ok || a.Status == "temperror":
			return nil, errTemporary
		case a.Status == "nxdomain":
			return nil, errNoRecord
		}
		return a.TXT, nil
	}
	v, err := Check(Input{Raw: raw, Recipient: req.Recipient, ReceivedAt: time.UnixMilli(req.ReceivedAt)}, lookup)
	if err != nil {
		return writeJSON(w, reply{Error: errUnreadable})
	}
	vb, err := json.Marshal(v)
	if err != nil {
		return err
	}
	return writeJSON(w, reply{Verdict: vb})
}

// Resolver answers the edge's TXT questions. It returns ErrNoRecord when the name
// has no TXT record; any other error is temporary.
type Resolver interface {
	TXT(ctx context.Context, name string) ([]string, error)
}

// ErrNoRecord is a Resolver's answer for a name with no TXT record.
var ErrNoRecord = errNoRecord

// keyNamePattern is a DKIM key name: selector labels, "_domainkey", then the
// domain. Letters, digits, hyphens and underscores, dot-separated.
var keyNamePattern = regexp.MustCompile(`^([A-Za-z0-9_]([A-Za-z0-9_-]{0,61}[A-Za-z0-9_])?\.)+_domainkey(\.[A-Za-z0-9_]([A-Za-z0-9_-]{0,61}[A-Za-z0-9_])?)+$`)

// ValidKeyName reports whether the edge may ask DNS about name.
func ValidKeyName(name string) bool {
	return len(name) <= 253 && keyNamePattern.MatchString(name)
}

// Process runs the check in a child process per message and answers its DNS
// questions.
type Process struct {
	// Command starts the child. SelfCommand is the edge's.
	Command func(ctx context.Context) *exec.Cmd
	// DNS answers the child's questions. Nil makes every lookup temporary, so
	// every signature is a temperror.
	DNS func() Resolver

	once  sync.Once
	slots chan struct{}
}

// Check returns the check JSON for one message, always: when the child fails, the
// JSON says it couldn't check. It never returns the child's error text, which
// could carry the message's content.
func (p *Process) Check(ctx context.Context, raw []byte, recipient string, receivedAt time.Time) []byte {
	p.once.Do(func() { p.slots = make(chan struct{}, maxChildren) })
	ctx, cancel := context.WithTimeout(ctx, Timeout)
	defer cancel()
	select {
	case p.slots <- struct{}{}:
		defer func() { <-p.slots }()
	case <-ctx.Done():
		return Failed("the edge was too busy to check the sender")
	}
	v, err := p.run(ctx, raw, recipient, receivedAt)
	if err != nil {
		log.Printf("sendercheck: check failed: %s", errClass(err))
		return Failed("the edge couldn't check the sender")
	}
	return v
}

// errClass names a failure without its text.
func errClass(err error) string {
	switch {
	case errors.Is(err, context.DeadlineExceeded):
		return "timed out"
	case errors.As(err, new(*exec.ExitError)):
		return "the child exited"
	case errors.Is(err, errVerdict):
		return "bad verdict"
	}
	return "child I/O"
}

var errVerdict = errors.New("sendercheck: bad verdict")

func (p *Process) run(ctx context.Context, raw []byte, recipient string, receivedAt time.Time) ([]byte, error) {
	var stdin io.WriteCloser
	var stdout io.ReadCloser
	cmd, err := start(func() *exec.Cmd { return p.Command(ctx) }, func(cmd *exec.Cmd) error {
		cmd.Env = []string{}
		cmd.Stderr = &capped{max: maxStderr}
		var err error
		if stdin, err = cmd.StdinPipe(); err != nil {
			return err
		}
		stdout, err = cmd.StdoutPipe()
		return err
	})
	if err != nil {
		return nil, err
	}
	out, convErr := p.converse(ctx, stdin, stdout, raw, recipient, receivedAt)
	stdin.Close()
	if convErr != nil {
		_ = cmd.Process.Kill()
	}
	waitErr := cmd.Wait()
	if convErr != nil {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		return nil, convErr
	}
	if waitErr != nil {
		return nil, waitErr
	}
	return out, nil
}

func (p *Process) converse(ctx context.Context, stdin io.Writer, stdout io.Reader, raw []byte, recipient string, receivedAt time.Time) ([]byte, error) {
	errc := make(chan error, 1)
	go func() {
		if err := writeJSON(stdin, request{Recipient: recipient, ReceivedAt: receivedAt.UnixMilli()}); err != nil {
			errc <- err
			return
		}
		errc <- writeFrame(stdin, raw)
	}()
	b, err := readFrame(stdout, maxReply)
	if err != nil {
		return nil, err
	}
	if err := <-errc; err != nil {
		return nil, err
	}
	var first reply
	if err := decodeStrict(b, &first); err != nil {
		return nil, errVerdict
	}
	if first.Error != "" {
		return childFailed(first.Error), nil
	}
	if len(first.Names) > maxSignatures {
		return nil, errVerdict
	}
	ans := answers{Answers: map[string]answer{}}
	var resolver Resolver
	if p.DNS != nil {
		resolver = p.DNS()
	}
	for _, name := range first.Names {
		ans.Answers[name] = p.lookup(ctx, resolver, name)
	}
	if err := writeJSON(stdin, ans); err != nil {
		return nil, err
	}
	b, err = readFrame(stdout, maxReply)
	if err != nil {
		return nil, err
	}
	var last reply
	if err := decodeStrict(b, &last); err != nil {
		return nil, errVerdict
	}
	if last.Error != "" {
		return childFailed(last.Error), nil
	}
	return finish(last.Verdict, raw)
}

// errUnreadable is the child's one reason a message can't be checked.
const errUnreadable = "the message header couldn't be read"

// childFailed stores the child's reason only when it's the one the child gives,
// so a child misled by the message can't write the message's text into the check.
func childFailed(why string) []byte {
	if why != errUnreadable {
		why = "the edge couldn't check the sender"
	}
	return Failed(why)
}

func (p *Process) lookup(ctx context.Context, r Resolver, name string) answer {
	if !ValidKeyName(name) {
		return answer{Status: "nxdomain"}
	}
	if r == nil {
		return answer{Status: "temperror"}
	}
	txt, err := r.TXT(ctx, name)
	switch {
	case errors.Is(err, ErrNoRecord):
		return answer{Status: "nxdomain"}
	case err != nil:
		return answer{Status: "temperror"}
	}
	return answer{TXT: txt}
}

// finish checks the child's verdict has the contract's shape, and sets the fields
// the edge vouches for itself.
func finish(b []byte, raw []byte) ([]byte, error) {
	var v Verdict
	if err := decodeStrict(b, &v); err != nil {
		return nil, errVerdict
	}
	if len(v.DKIM) > maxSignatures {
		return nil, errVerdict
	}
	if v.DKIM == nil {
		v.DKIM = []Signature{}
	}
	for i := range v.DKIM {
		if v.DKIM[i].Headers == nil {
			v.DKIM[i].Headers = []string{}
		}
	}
	v.V, v.CheckedBy = Version, "edge"
	sum := sha256.Sum256(raw)
	v.RawSHA256 = hex.EncodeToString(sum[:])
	out, err := json.Marshal(v)
	if err != nil || len(out) > MaxBytes {
		return nil, errVerdict
	}
	return out, nil
}

// SelfCommand starts this binary as the child.
func SelfCommand() (func(ctx context.Context) *exec.Cmd, error) {
	exe, err := os.Executable()
	if err != nil {
		return nil, err
	}
	return func(ctx context.Context) *exec.Cmd {
		return exec.CommandContext(ctx, exe, Subcommand)
	}, nil
}

// capped keeps the first max bytes written to it.
type capped struct {
	buf bytes.Buffer
	max int
}

func (c *capped) Write(p []byte) (int, error) {
	if room := c.max - c.buf.Len(); room > 0 {
		c.buf.Write(p[:min(room, len(p))])
	}
	return len(p), nil
}
