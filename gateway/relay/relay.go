package main

import (
	"bufio"
	"context"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"net/netip"
	"strings"
	"sync"
	"time"
)

const (
	requestTimeout = 10 * time.Second // handshake plus the CONNECT request
	dialTimeout    = 10 * time.Second // per address
	idleTimeout    = 5 * time.Minute  // per read, either direction
	maxLifetime    = 30 * time.Minute // one relayed stream
	maxRequest     = 4096             // CONNECT line plus headers
	maxHeaderLines = 32
)

// Relay serves the edge's CONNECT requests (internal/send/relay.go). The listener
// it's given has already done mutual TLS 1.3 with the edge's pinned client key.
// It never logs: a destination names a recipient's mail provider.
type Relay struct {
	// Lookup resolves a name. Nil uses the system resolver.
	Lookup func(ctx context.Context, host string) ([]netip.Addr, error)
	// Dial opens the upstream connection to an address Lookup gave and the
	// rules passed. Nil uses a net.Dialer that re-checks the address on the socket.
	Dial func(ctx context.Context, addr netip.AddrPort) (net.Conn, error)
	// MaxConns bounds open streams; past it, new connections are closed at once.
	MaxConns int
}

// Serve accepts until ln fails, which it returns.
func (r *Relay) Serve(ln net.Listener) error {
	slots := make(chan struct{}, max(r.MaxConns, 1))
	for {
		c, err := ln.Accept()
		if err != nil {
			var ne net.Error
			if errors.As(err, &ne) && ne.Timeout() {
				time.Sleep(50 * time.Millisecond)
				continue
			}
			return err
		}
		select {
		case slots <- struct{}{}:
			go func() {
				defer func() { <-slots }()
				r.handle(c)
			}()
		default:
			c.Close()
		}
	}
}

func (r *Relay) handle(c net.Conn) {
	defer c.Close()
	ctx, cancel := context.WithTimeout(context.Background(), maxLifetime)
	defer cancel()

	_ = c.SetDeadline(time.Now().Add(requestTimeout))
	if tc, ok := c.(*tls.Conn); ok {
		if err := tc.HandshakeContext(ctx); err != nil {
			return
		}
	}
	br := bufio.NewReaderSize(c, maxRequest)
	authority, err := readConnect(br)
	if err != nil {
		reply(c, "400 Bad Request")
		return
	}
	up, status := r.open(ctx, authority)
	if up == nil {
		reply(c, status)
		return
	}
	defer up.Close()
	if !reply(c, "200 Connection established") {
		return
	}
	_ = c.SetDeadline(time.Time{})
	stop := context.AfterFunc(ctx, func() { c.Close(); up.Close() })
	defer stop()
	splice(c, br, up)
}

// open checks authority, resolves it once, checks every address, and dials only
// those. On refusal it returns nil and the status line to send.
func (r *Relay) open(ctx context.Context, authority string) (net.Conn, string) {
	t, err := checkTarget(authority)
	if err != nil {
		return nil, "403 Forbidden"
	}
	addrs := []netip.Addr{t.ip}
	if t.name != "" {
		lctx, cancel := context.WithTimeout(ctx, requestTimeout)
		addrs, err = r.lookup(lctx, t.name)
		cancel()
		if err != nil || len(addrs) == 0 {
			return nil, "502 Bad Gateway"
		}
		// One non-public answer refuses the name outright, rather than quietly
		// using the rest: a name that points inside isn't a mail server.
		for _, a := range addrs {
			if !publicAddr(a) {
				return nil, "403 Forbidden"
			}
		}
	}
	for _, a := range addrs {
		dctx, cancel := context.WithTimeout(ctx, dialTimeout)
		up, err := r.dial(dctx, netip.AddrPortFrom(a.Unmap(), t.port))
		cancel()
		if err == nil {
			return up, ""
		}
	}
	return nil, "502 Bad Gateway"
}

func (r *Relay) lookup(ctx context.Context, host string) ([]netip.Addr, error) {
	if r.Lookup != nil {
		return r.Lookup(ctx, host)
	}
	return net.DefaultResolver.LookupNetIP(ctx, "ip", host)
}

func (r *Relay) dial(ctx context.Context, ap netip.AddrPort) (net.Conn, error) {
	if r.Dial != nil {
		return r.Dial(ctx, ap)
	}
	d := net.Dialer{Control: checkDialed}
	return d.DialContext(ctx, "tcp", ap.String())
}

// readConnect reads one request in the form the edge sends:
//
//	CONNECT host:port HTTP/1.1
//	Host: host:port
//
// Headers are read and ignored; only the request line names the destination.
func readConnect(br *bufio.Reader) (string, error) {
	total := 0
	line := func() (string, error) {
		s, err := br.ReadString('\n')
		total += len(s)
		if err != nil {
			return "", err
		}
		if total > maxRequest {
			return "", errors.New("request too long")
		}
		return strings.TrimSuffix(strings.TrimSuffix(s, "\n"), "\r"), nil
	}
	first, err := line()
	if err != nil {
		return "", err
	}
	method, rest, ok1 := strings.Cut(first, " ")
	authority, proto, ok2 := strings.Cut(rest, " ")
	if !ok1 || !ok2 || method != "CONNECT" || (proto != "HTTP/1.1" && proto != "HTTP/1.0") || authority == "" {
		return "", errors.New("not a CONNECT request")
	}
	for i := 0; ; i++ {
		if i == maxHeaderLines {
			return "", errors.New("too many header lines")
		}
		h, err := line()
		if err != nil {
			return "", err
		}
		if h == "" {
			return authority, nil
		}
	}
}

func reply(c net.Conn, status string) bool {
	extra := ""
	if !strings.HasPrefix(status, "200 ") {
		extra = "Content-Length: 0\r\nConnection: close\r\n"
	}
	_, err := io.WriteString(c, "HTTP/1.1 "+status+"\r\n"+extra+"\r\n")
	return err == nil
}

// splice copies both ways until both sides finish. A clean end (EOF) half-closes
// the other side's write, so SMTP's QUIT and its reply both get through; any
// other end, such as an idle deadline or a reset, closes both. Every read has an
// idle deadline.
func splice(client net.Conn, fromClient io.Reader, up net.Conn) {
	var wg sync.WaitGroup
	wg.Add(2)
	pipe := func(dst net.Conn, src io.Reader, deadlineOn net.Conn) {
		defer wg.Done()
		if err := copyIdle(dst, src, deadlineOn); err != nil {
			client.Close()
			up.Close()
			return
		}
		closeWrite(dst)
	}
	go pipe(up, fromClient, client)
	go pipe(client, up, up)
	wg.Wait()
}

// copyIdle copies src to dst, renewing deadlineOn's read deadline before each
// read. It returns nil at EOF.
func copyIdle(dst io.Writer, src io.Reader, deadlineOn net.Conn) error {
	buf := make([]byte, 32<<10)
	for {
		_ = deadlineOn.SetReadDeadline(time.Now().Add(idleTimeout))
		n, err := src.Read(buf)
		if n > 0 {
			if _, werr := dst.Write(buf[:n]); werr != nil {
				return werr
			}
		}
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return err
		}
	}
}

func closeWrite(c net.Conn) {
	if cw, ok := c.(interface{ CloseWrite() error }); ok {
		if cw.CloseWrite() == nil {
			return
		}
	}
	c.Close()
}
