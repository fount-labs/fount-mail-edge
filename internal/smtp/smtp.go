// Package smtp is the edge's inbound SMTP listener on the tunnelled port.
//
// It is deliberately small and strict (design §6, §7):
//
//   - The connection arrives through the gateway's attested tunnel, which
//     prepends a PROXY header carrying the real sender IP. A connection with no
//     PROXY header is dropped (the public port-25 move in §20 rejects it instead).
//   - STARTTLS is mandatory in the enclave, terminated with the attested key's
//     CA cert. Senders that won't use TLS are refused.
//   - Unknown recipients are rejected during SMTP; there is no catch-all.
//   - Bare LF / bare CR are rejected, in commands and in message bodies, and the
//     buffer is cleared after STARTTLS.
//   - Size and (later) per-mailbox / per-IP / per-sender limits apply.
//   - The edge never parses MIME; it stores each raw message whole and answers
//     250 only after the store confirms the write.
//
// This version implements the state machine and the strict framing; storage is
// whatever store.Store it is given (discarding, until M2 step 4).
package smtp

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/netip"
	"strings"
	"sync"
	"time"

	"github.com/fount-labs/fount-mail-edge/internal/limit"
	"github.com/fount-labs/fount-mail-edge/internal/store"
)

const (
	maxLineBytes = 8192 // an SMTP command line, CRLF included
	drainTimeout = 2 * time.Second
	drainBytes   = 1 << 20

	maxDomainBytes = 253 // the longest a DNS name can be
)

var (
	errLineTooLong  = errors.New("line too long")
	errTooLarge     = errors.New("message too large")
	errBareNewline  = errors.New("bare CR or LF in message")
	errClosedInData = errors.New("connection closed mid-DATA")
)

type CertSource interface {
	Current() (*tls.Certificate, bool)
}

type Storer interface {
	Put(ctx context.Context, recipient, sender string, raw []byte) (string, error)
}

// RecipientStatus is RCPT's verdict for one envelope recipient (§6, §4).
type RecipientStatus int

const (
	// RecipientUnknown: no mailbox claims the address. There is no catch-all
	// (§6), so RCPT answers 550 "no such user".
	RecipientUnknown RecipientStatus = iota
	// RecipientAccepting: a mailbox claims the address and its entitlement is
	// current. Deliver.
	RecipientAccepting
	// RecipientExpired: a mailbox claims the address but its entitlement has
	// lapsed past the past_due grace (§4 "after past_due grace, the mailbox
	// answers 550"). RCPT answers 550 so mail bounces rather than being
	// silently accepted and dropped.
	RecipientExpired
)

// RecipientChecker decides whether the edge accepts mail for an address right
// now. When an Options.Recipients is set, RCPT rejects anything it doesn't know
// (no catch-all, §6) and anything whose entitlement has lapsed (§4). A nil
// Recipients falls back to the domain suffix check alone, which is only right
// for dev/smoke where no routing data exists.
type RecipientChecker interface {
	Status(ctx context.Context, recipient string) (RecipientStatus, error)
}

type Options struct {
	Addr       string
	Hostname   string // HELO name, e.g. mx.fountbox.com
	Domain     string // accepted recipient domain, e.g. @fountbox.com
	Certs      CertSource
	Store      Storer
	Recipients RecipientChecker // optional; nil = domain suffix check only
	MaxBytes   int64
	MaxConns   int
	MaxPerIP   int           // connections at once from one source; 0 = 8
	Idle       time.Duration // the longest a read or write can wait; 0 = 2m
	MaxSession time.Duration // the longest a connection can last; 0 = 20m, which lets a 25 MB message take a slow link

	// PerIP and PerSender are rolling byte budgets that slow a flood (§6): a
	// source IP or sender domain that pushes more than its budget in the window
	// is answered 452 so it retries later. nil builds per-enclave defaults sized
	// comfortably above a single max message; inject a small one in tests.
	PerIP       *limit.Limiter
	PerSender   *limit.Limiter
	QuotaWindow time.Duration // window the default budgets refill over; 0 = 1h

	// PerIPMessages counts messages per source, because a byte budget doesn't feel
	// empty ones and each stored message costs a routing write. PerIPMisses is what
	// a source can spend on RCPT misses before it's disconnected, so the address
	// space can't be walked (§4). nil builds defaults.
	PerIPMessages *limit.Limiter
	PerIPMisses   *limit.Limiter
}

type Server struct {
	opt       Options
	ln        net.Listener
	wg        sync.WaitGroup
	sem       chan struct{}
	perIP     *limit.Limiter
	perSender *limit.Limiter
	perIPMsgs *limit.Limiter
	misses    *limit.Limiter

	mu      sync.Mutex
	sources map[string]int // open connections per source
}

func New(o Options) *Server {
	if o.MaxConns <= 0 {
		o.MaxConns = 50
	}
	if o.MaxPerIP <= 0 {
		o.MaxPerIP = 8
	}
	if o.Idle <= 0 {
		o.Idle = 2 * time.Minute
	}
	if o.MaxSession <= 0 {
		o.MaxSession = 20 * time.Minute
	}
	if !strings.HasPrefix(o.Domain, "@") {
		o.Domain = "@" + o.Domain
	}
	window := o.QuotaWindow
	if window <= 0 {
		window = time.Hour
	}
	perIP := o.PerIP
	if perIP == nil {
		perIP = limit.PerWindow(512<<20, window) // 512 MiB/IP/hour
	}
	perSender := o.PerSender
	if perSender == nil {
		perSender = limit.PerWindow(256<<20, window) // 256 MiB/sender-domain/hour
	}
	perIPMsgs := o.PerIPMessages
	if perIPMsgs == nil {
		perIPMsgs = limit.PerWindow(600, window) // 600 messages/IP/hour
	}
	misses := o.PerIPMisses
	if misses == nil {
		misses = limit.New(1.0/6, 20) // 20 misses, then 10 a minute
	}
	return &Server{
		opt: o, sem: make(chan struct{}, o.MaxConns), perIP: perIP, perSender: perSender,
		perIPMsgs: perIPMsgs, misses: misses, sources: map[string]int{},
	}
}

// admit counts a connection against its source, or reports that it's over the cap.
// Without this one source could hold every slot and lock everyone else out.
func (s *Server) admit(src string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.sources[src] >= s.opt.MaxPerIP {
		return false
	}
	s.sources[src]++
	return true
}

func (s *Server) release(src string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.sources[src]--; s.sources[src] <= 0 {
		delete(s.sources, src)
	}
}

func (s *Server) ListenAndServe(ctx context.Context) error {
	ln, err := net.Listen("tcp", s.opt.Addr)
	if err != nil {
		return err
	}
	return s.Serve(ctx, ln)
}

// Serve runs the state machine on an already-open listener; ListenAndServe calls
// it after binding s.opt.Addr. Tests serve on 127.0.0.1:0 and read the chosen
// address back off the listener, so the conversation harness needs no fixed port.
func (s *Server) Serve(ctx context.Context, ln net.Listener) error {
	s.ln = ln
	go func() {
		<-ctx.Done()
		_ = ln.Close()
	}()
	for {
		conn, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			var ne net.Error
			//lint:ignore SA1019 Temporary() is deprecated but is still the only
			// portable signal for a transient Accept error; a brief retry here is
			// intentional and cannot be expressed otherwise.
			if errors.As(err, &ne) && ne.Temporary() {
				continue
			}
			return err
		}
		select {
		case s.sem <- struct{}{}:
			s.wg.Add(1)
			go func() {
				defer s.wg.Done()
				defer func() { <-s.sem }()
				s.handle(ctx, conn)
			}()
		default:
			_ = conn.Close() // over the per-enclave connection cap
		}
	}
}

func (s *Server) Shutdown(ctx context.Context) error {
	if s.ln != nil {
		_ = s.ln.Close()
	}
	done := make(chan struct{})
	go func() { s.wg.Wait(); close(done) }()
	select {
	case <-done:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

type session struct {
	s         *Server
	conn      net.Conn
	timer     *deadlineConn
	r         *bufio.Reader
	tls       bool
	srcIP     string
	hasMail   bool // MAIL was accepted, which the sender can't show: <> is valid
	recipient string
	sender    string
}

// deadlineConn gives each read and write the idle timeout, up to a fixed end for
// the connection. A slow sender that keeps moving can finish, and a trickle can't
// hold a slot forever. It sits under TLS, so it times the handshake too.
type deadlineConn struct {
	net.Conn
	idle time.Duration
	end  time.Time
}

func (c *deadlineConn) refresh() {
	d := time.Now().Add(c.idle)
	if c.end.Before(d) {
		d = c.end
	}
	_ = c.Conn.SetDeadline(d)
}

func (c *deadlineConn) Read(p []byte) (int, error) {
	c.refresh()
	return c.Conn.Read(p)
}

func (c *deadlineConn) Write(p []byte) (int, error) {
	c.refresh()
	return c.Conn.Write(p)
}

func (s *Server) handle(ctx context.Context, conn net.Conn) {
	defer conn.Close()
	timer := &deadlineConn{Conn: conn, idle: s.opt.Idle, end: time.Now().Add(s.opt.MaxSession)}
	conn = timer
	se := &session{s: s, conn: conn, timer: timer, r: bufio.NewReader(conn)}

	// The gateway prepends exactly one PROXY header before anything else.
	if ok := se.readProxyHeader(); !ok {
		return
	}
	if !s.admit(se.srcIP) {
		se.reply("421 4.7.0 too many connections from your address")
		return
	}
	defer s.release(se.srcIP)
	cert, ready := s.opt.Certs.Current()
	if !ready {
		se.reply("421 4.3.2 %s certificate not ready", s.opt.Hostname)
		return
	}
	se.reply("220 %s ESMTP", s.opt.Hostname)

	for {
		line, err := se.readLine()
		if err != nil {
			return
		}
		verb, rest := splitVerb(line)
		switch verb {
		case "EHLO", "HELO":
			if se.tls {
				se.reply("250-%s\r\n250 SIZE %d", s.opt.Hostname, s.opt.MaxBytes)
			} else {
				se.reply("250-%s\r\n250-SIZE %d\r\n250 STARTTLS", s.opt.Hostname, s.opt.MaxBytes)
			}
		case "STARTTLS":
			if se.tls {
				se.reply("503 5.5.1 already in TLS")
				continue
			}
			se.reply("220 go ahead")
			tc := tls.Server(conn, &tls.Config{
				Certificates: []tls.Certificate{*cert},
				MinVersion:   tls.VersionTLS12,
			})
			if err := tc.HandshakeContext(ctx); err != nil {
				return
			}
			conn = tc
			se.conn = tc
			se.r = bufio.NewReader(tc) // clear buffered plaintext after STARTTLS
			se.tls = true
			se.endTransaction()
		case "MAIL", "RCPT", "DATA":
			if !se.tls {
				se.reply("530 5.7.0 Must issue a STARTTLS command first")
				continue
			}
			if !se.command(ctx, verb, rest) {
				return
			}
		case "NOOP":
			se.reply("250 ok")
		case "RSET":
			se.endTransaction()
			se.reply("250 ok")
		case "QUIT":
			se.reply("221 bye")
			return
		default:
			se.reply("502 5.5.1 not implemented")
		}
	}
}

func (se *session) endTransaction() {
	se.hasMail, se.recipient, se.sender = false, "", ""
}

// miss answers a recipient that doesn't exist, and reports false once this source
// has used up what it can spend on them.
func (se *session) miss() bool {
	if !se.s.misses.Allow(se.srcIP) {
		se.reply("421 4.7.1 too many unknown recipients")
		return false
	}
	se.reply("550 5.1.1 no such user")
	return true
}

// command runs one mail verb. It returns false when the connection must close,
// which is any time a message's framing can't be trusted: whatever follows could
// be another sender's bytes read as commands.
func (se *session) command(ctx context.Context, verb, rest string) bool {
	switch verb {
	case "MAIL":
		sender := extractAddr(rest)
		if len(senderDomain(sender)) > maxDomainBytes {
			se.reply("553 5.1.3 sender domain too long")
			return true
		}
		se.hasMail, se.recipient, se.sender = true, "", sender
		se.reply("250 ok")
	case "RCPT":
		if !se.hasMail {
			se.reply("503 5.5.1 need MAIL")
			return true
		}
		// One transaction is one stored copy for one recipient. Accepting a second
		// would have to store two and could fail between them, so ask the sender to
		// retry it separately.
		if se.recipient != "" {
			se.reply("452 4.5.3 too many recipients, send separately")
			return true
		}
		addr := extractAddr(rest)
		if !strings.HasSuffix(strings.ToLower(addr), strings.ToLower(se.s.opt.Domain)) {
			return se.miss()
		}
		if rc := se.s.opt.Recipients; rc != nil {
			switch st, err := rc.Status(ctx, addr); {
			case err != nil:
				se.reply("451 4.3.0 try again later")
				return true
			case st == RecipientUnknown:
				return se.miss()
			case st == RecipientExpired:
				se.reply("550 5.7.1 mailbox not accepting mail")
				return true
			}
		}
		se.recipient = addr
		se.reply("250 ok")
	case "DATA":
		if se.recipient == "" {
			se.reply("503 5.5.1 need RCPT")
			return true
		}
		se.reply("354 end with <CRLF>.<CRLF>")
		raw, err := se.readData()
		recipient, sender := se.recipient, se.sender
		se.endTransaction()
		switch {
		case errors.Is(err, errBareNewline):
			se.reply("554 5.6.0 message rejected: %v", err)
			se.drain()
			return false
		case err != nil:
			se.reply("552 5.3.4 message rejected: %v", err)
			se.drain()
			return false
		}
		// Rolling byte budgets slow a flood (§6). A sender can't be verified, so
		// cap what one source IP or sender domain can push per window; 452 asks it
		// to retry later rather than bouncing legitimate mail outright.
		n := float64(len(raw))
		if !se.s.perIPMsgs.Allow(se.srcIP) {
			se.reply("452 4.3.1 source over rate limit, retry later")
			return true
		}
		if !se.s.perIP.AllowN(se.srcIP, n) {
			se.reply("452 4.3.1 source over rate limit, retry later")
			return true
		}
		if dom := senderDomain(sender); dom != "" && !se.s.perSender.AllowN(dom, n) {
			se.reply("452 4.3.1 sender domain over rate limit, retry later")
			return true
		}
		id, err := se.s.opt.Store.Put(ctx, recipient, sender, raw)
		if errors.Is(err, store.ErrConflict) {
			// Another edge wrote routing data first, as happens during a deploy.
			se.reply("451 4.3.0 try again shortly")
			return true
		}
		if err != nil {
			// S3 not confirmed: do NOT 250. 452 asks the sender to retry.
			se.reply("452 4.3.0 temporary storage failure")
			log.Printf("smtp: store failed: %s", storeErrClass(err))
			return true
		}
		se.reply("250 2.0.0 stored %s", id)
	}
	return true
}

// storeErrClass names a store failure without its text, because the text can carry
// the recipient or an S3 key with the mailbox ID, and a sender can cause failures
// on purpose by filling a mailbox.
func storeErrClass(err error) string {
	switch {
	case errors.Is(err, store.ErrMailboxFull):
		return "mailbox-full"
	case errors.Is(err, store.ErrNoRecipient):
		return "no-recipient"
	case errors.Is(err, store.ErrNotFound):
		return "not-found"
	case errors.Is(err, context.DeadlineExceeded):
		return "timeout"
	case errors.Is(err, context.Canceled):
		return "canceled"
	default:
		return "other"
	}
}

// readProxyHeader consumes the single PROXY v1 line and records the source, as the
// key for every per-source limit. One host can hold a whole IPv6 /64, so that's the
// unit there.
func (se *session) readProxyHeader() bool {
	line, err := se.readLine()
	if err != nil {
		return false
	}
	// PROXY TCP4 <src> <dst> <sport> <dport>
	f := strings.Fields(line)
	if len(f) != 6 || f[0] != "PROXY" || (f[1] != "TCP4" && f[1] != "TCP6") {
		return false
	}
	ip, err := netip.ParseAddr(f[2])
	if err != nil {
		return false
	}
	ip = ip.Unmap()
	if ip.Is6() {
		ip = netip.PrefixFrom(ip, 64).Masked().Addr()
	}
	se.srcIP = ip.String()
	return true
}

func (se *session) readLine() (string, error) {
	line, err := se.readBounded(nil, maxLineBytes)
	if err != nil {
		return "", err
	}
	// Reject bare LF / bare CR: a valid command line ends in CRLF.
	if !bytes.HasSuffix(line, []byte("\r\n")) {
		return "", errors.New("bare LF")
	}
	body := line[:len(line)-2]
	if bytes.ContainsRune(body, '\r') || bytes.ContainsRune(body, '\n') {
		return "", errors.New("bare CR/LF in line")
	}
	return string(body), nil
}

// readBounded reads through the next LF into line's storage. It stops with
// errLineTooLong as soon as the line passes max, so a peer that never sends LF
// costs no more than max bytes.
func (se *session) readBounded(line []byte, max int) ([]byte, error) {
	line = line[:0]
	for {
		frag, err := se.r.ReadSlice('\n')
		if len(line)+len(frag) > max {
			return nil, errLineTooLong
		}
		line = append(line, frag...)
		if err == nil {
			return line, nil
		}
		if !errors.Is(err, bufio.ErrBufferFull) {
			return nil, err
		}
	}
}

// readData reads the DATA body until <CRLF>.<CRLF>, enforcing the size cap and
// undoing dot-stuffing. It returns the raw message bytes.
//
// Every line must end in CRLF, with no CR or LF inside it. Otherwise a bare LF
// could end the message here while a mail system that framed it differently saw
// one message, and the rest would run as a new transaction under the relay's
// source IP. Any error here means the reader has stopped mid-message, so the
// caller must close the connection rather than read commands from what's left.
func (se *session) readData() ([]byte, error) {
	var buf bytes.Buffer
	var line []byte
	for {
		// The room left, plus enough for the terminator.
		room := se.s.opt.MaxBytes - int64(buf.Len()) + int64(len(".\r\n"))
		var err error
		line, err = se.readBounded(line, int(room))
		switch {
		case errors.Is(err, errLineTooLong):
			return nil, errTooLarge
		case err != nil:
			return nil, errClosedInData
		}
		if !bytes.HasSuffix(line, []byte("\r\n")) || bytes.IndexByte(line[:len(line)-2], '\r') >= 0 {
			return nil, errBareNewline
		}
		if bytes.Equal(line, []byte(".\r\n")) {
			return buf.Bytes(), nil
		}
		content := line
		if bytes.HasPrefix(content, []byte("..")) {
			content = content[1:] // undo dot-stuffing
		}
		if int64(buf.Len()+len(content)) > se.s.opt.MaxBytes {
			return nil, errTooLarge
		}
		buf.Write(content)
	}
}

// drain reads a little of what's still arriving before a rejected connection
// closes. Closing with unread data resets the connection, which can destroy the
// reply before a sender still writing its message reads it.
func (se *session) drain() {
	se.timer.end = time.Now().Add(drainTimeout)
	_, _ = io.CopyN(io.Discard, se.r, drainBytes)
}

func (se *session) reply(format string, a ...any) {
	fmt.Fprintf(se.conn, format+"\r\n", a...)
}

func splitVerb(line string) (verb, rest string) {
	line = strings.TrimSpace(line)
	if i := strings.IndexByte(line, ' '); i >= 0 {
		return strings.ToUpper(line[:i]), line[i+1:]
	}
	return strings.ToUpper(line), ""
}

// senderDomain is the lowercased domain of an envelope sender, used to key the
// per-sender byte budget. An empty return (no '@', e.g. the null sender <>)
// skips the per-sender check, which only ever adds a brake.
func senderDomain(sender string) string {
	if i := strings.LastIndexByte(sender, '@'); i >= 0 && i < len(sender)-1 {
		return strings.ToLower(sender[i+1:])
	}
	return ""
}

// extractAddr pulls the address out of "FROM:<a@b>" / "TO:<a@b>" style args.
func extractAddr(rest string) string {
	if i := strings.IndexByte(rest, '<'); i >= 0 {
		if j := strings.IndexByte(rest[i:], '>'); j >= 0 {
			return rest[i+1 : i+j]
		}
	}
	if i := strings.IndexByte(rest, ':'); i >= 0 {
		return strings.TrimSpace(rest[i+1:])
	}
	return strings.TrimSpace(rest)
}
