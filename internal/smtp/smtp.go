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
//   - Bare LF / bare CR are rejected and the buffer is cleared after STARTTLS.
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
	"strings"
	"sync"
	"time"
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
	Deadline   time.Duration
}

type Server struct {
	opt Options
	ln  net.Listener
	wg  sync.WaitGroup
	sem chan struct{}
}

func New(o Options) *Server {
	if o.MaxConns <= 0 {
		o.MaxConns = 50
	}
	if o.Deadline <= 0 {
		o.Deadline = 2 * time.Minute
	}
	if !strings.HasPrefix(o.Domain, "@") {
		o.Domain = "@" + o.Domain
	}
	return &Server{opt: o, sem: make(chan struct{}, o.MaxConns)}
}

func (s *Server) ListenAndServe(ctx context.Context) error {
	ln, err := net.Listen("tcp", s.opt.Addr)
	if err != nil {
		return err
	}
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
			if errors.As(err, &ne) && ne.Temporary() { //nolint:staticcheck // transient accept errors
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
	r         *bufio.Reader
	tls       bool
	srcIP     string
	recipient string
	sender    string
}

func (s *Server) handle(ctx context.Context, conn net.Conn) {
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(s.opt.Deadline))
	se := &session{s: s, conn: conn, r: bufio.NewReader(conn)}

	// The gateway prepends exactly one PROXY header before anything else.
	if ok := se.readProxyHeader(); !ok {
		return
	}
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
			se.recipient, se.sender = "", ""
		case "MAIL", "RCPT", "DATA":
			if !se.tls {
				se.reply("530 5.7.0 Must issue a STARTTLS command first")
				continue
			}
			se.command(ctx, verb, rest)
		case "NOOP":
			se.reply("250 ok")
		case "RSET":
			se.recipient, se.sender = "", ""
			se.reply("250 ok")
		case "QUIT":
			se.reply("221 bye")
			return
		default:
			se.reply("502 5.5.1 not implemented")
		}
	}
}

func (se *session) command(ctx context.Context, verb, rest string) {
	switch verb {
	case "MAIL":
		se.recipient = ""
		se.sender = extractAddr(rest)
		se.reply("250 ok")
	case "RCPT":
		addr := extractAddr(rest)
		if !strings.HasSuffix(strings.ToLower(addr), strings.ToLower(se.s.opt.Domain)) {
			se.reply("550 5.1.1 no such user")
			return
		}
		if rc := se.s.opt.Recipients; rc != nil {
			switch st, err := rc.Status(ctx, addr); {
			case err != nil:
				se.reply("451 4.3.0 try again later")
				return
			case st == RecipientUnknown:
				se.reply("550 5.1.1 no such user")
				return
			case st == RecipientExpired:
				se.reply("550 5.7.1 mailbox not accepting mail")
				return
			}
		}
		se.recipient = addr
		se.reply("250 ok")
	case "DATA":
		if se.recipient == "" {
			se.reply("503 5.5.1 need RCPT")
			return
		}
		se.reply("354 end with <CRLF>.<CRLF>")
		raw, err := se.readData()
		if err != nil {
			se.reply("552 5.3.4 message rejected: %v", err)
			return
		}
		id, err := se.s.opt.Store.Put(ctx, se.recipient, se.sender, raw)
		if err != nil {
			// S3 not confirmed: do NOT 250. 452 asks the sender to retry.
			se.reply("452 4.3.0 temporary storage failure")
			log.Printf("smtp: store failed for %s: %v", se.recipient, err)
			return
		}
		se.reply("250 2.0.0 stored %s", id)
		se.recipient = ""
	}
}

// readProxyHeader consumes the single PROXY v1 line and records the source IP.
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
	se.srcIP = f[2]
	return true
}

func (se *session) readLine() (string, error) {
	line, err := se.r.ReadBytes('\n')
	if err != nil {
		return "", err
	}
	if len(line) > 8192 {
		return "", errors.New("line too long")
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

// readData reads the DATA body until <CRLF>.<CRLF>, enforcing the size cap and
// undoing dot-stuffing. It returns the raw message bytes.
func (se *session) readData() ([]byte, error) {
	var buf bytes.Buffer
	lr := &io.LimitedReader{R: se.r, N: se.s.opt.MaxBytes + 1024}
	br := bufio.NewReader(lr)
	for {
		line, err := br.ReadBytes('\n')
		if err != nil {
			return nil, errors.New("connection closed mid-DATA")
		}
		if int64(buf.Len()) > se.s.opt.MaxBytes {
			return nil, errors.New("message too large")
		}
		if bytes.Equal(line, []byte(".\r\n")) {
			break
		}
		if bytes.HasPrefix(line, []byte("..")) {
			line = line[1:] // undo dot-stuffing
		}
		buf.Write(line)
	}
	return buf.Bytes(), nil
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
