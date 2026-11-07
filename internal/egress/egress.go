// Package egress carries the edge's S3 traffic out of the enclave (design §6).
//
// S3 doesn't work through Tinfoil's hostname allowlist, so a second container runs
// Forwarder: the only container on an open network, with one fixed route per
// bucket hostname. The edge reaches it over a closed network with NewHTTPClient and
// picks a destination only by picking a route's port.
//
// The forwarder copies bytes and parses nothing. TLS runs from the edge to S3, so
// the forwarder never sees a request, a credential, or a message.
package egress

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"math/rand/v2"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	s3Port = "443"

	// idleTimeout applies to each direction, so it must outlast one S3 request,
	// which the S3 client limits to 30 seconds. The edge drops pooled connections
	// after edgeIdleTimeout, before this fires.
	idleTimeout     = 2 * time.Minute
	edgeIdleTimeout = time.Minute

	dialTimeout   = 5 * time.Second // one S3 address
	dialBudget    = 20 * time.Second
	maxConns      = 256 // at most 128 tunnels feed the edge, and each may hold one S3 connection
	maxBufferSize = 32 << 10

	forwarderDialTimeout = 3 * time.Second
)

// forwarderRetries are the waits between tries at the forwarder. The containers
// start in parallel, and the forwarder may be restarting.
var forwarderRetries = []time.Duration{250 * time.Millisecond, 500 * time.Millisecond, time.Second, 2 * time.Second, 4 * time.Second}

// Route sends connections on Port to Host:443.
type Route struct {
	Port int
	Host string
}

// ParseRoutes reads "9001=bucket.example,9002=other.example". The value is
// measured, so both containers and any outside reader see the same routes.
func ParseRoutes(s string) ([]Route, error) {
	var routes []Route
	ports, hosts := map[int]bool{}, map[string]bool{}
	for _, f := range strings.Split(s, ",") {
		port, host, ok := strings.Cut(strings.TrimSpace(f), "=")
		if !ok {
			return nil, fmt.Errorf("route %q: want port=host", f)
		}
		n, err := strconv.Atoi(port)
		if err != nil || n < 1024 || n > 65535 {
			return nil, fmt.Errorf("route %q: bad port", f)
		}
		if host == "" || strings.ContainsAny(host, ":/ ") {
			return nil, fmt.Errorf("route %q: bad host", f)
		}
		if ports[n] || hosts[host] {
			return nil, fmt.Errorf("route %q: duplicate", f)
		}
		ports[n], hosts[host] = true, true
		routes = append(routes, Route{Port: n, Host: host})
	}
	return routes, nil
}

// Forwarder relays connections along fixed routes.
type Forwarder struct {
	Routes []Route

	// The rest are set by tests.
	lookup   func(ctx context.Context, host string) ([]net.IP, error)
	dial     func(ctx context.Context, addr string) (net.Conn, error)
	idle     time.Duration
	capacity int
}

// Serve listens on every route until ctx ends or a listener fails.
func (f *Forwarder) Serve(ctx context.Context) error {
	if len(f.Routes) == 0 {
		return errors.New("egress: no routes")
	}
	var lc net.ListenConfig
	listeners := make([]net.Listener, 0, len(f.Routes))
	defer func() {
		for _, ln := range listeners {
			_ = ln.Close()
		}
	}()
	for _, r := range f.Routes {
		ln, err := lc.Listen(ctx, "tcp", net.JoinHostPort("", strconv.Itoa(r.Port)))
		if err != nil {
			return err
		}
		listeners = append(listeners, ln)
	}
	return f.serve(ctx, listeners)
}

func (f *Forwarder) serve(ctx context.Context, listeners []net.Listener) error {
	f.defaults()
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	go func() {
		<-ctx.Done()
		for _, ln := range listeners {
			_ = ln.Close()
		}
	}()
	slots := make(chan struct{}, f.capacity)
	errc := make(chan error, len(listeners))
	for i, ln := range listeners {
		go func() { errc <- f.accept(ctx, ln, f.Routes[i].Host, slots) }()
	}
	err := <-errc
	if ctx.Err() != nil {
		return nil
	}
	return err
}

func (f *Forwarder) defaults() {
	if f.lookup == nil {
		f.lookup = func(ctx context.Context, host string) ([]net.IP, error) {
			return net.DefaultResolver.LookupIP(ctx, "ip4", host)
		}
	}
	if f.dial == nil {
		d := net.Dialer{Timeout: dialTimeout}
		f.dial = func(ctx context.Context, addr string) (net.Conn, error) {
			return d.DialContext(ctx, "tcp", addr)
		}
	}
	if f.idle == 0 {
		f.idle = idleTimeout
	}
	if f.capacity == 0 {
		f.capacity = maxConns
	}
}

func (f *Forwarder) accept(ctx context.Context, ln net.Listener, host string, slots chan struct{}) error {
	for {
		c, err := ln.Accept()
		if err != nil {
			return fmt.Errorf("egress: accept for %s: %w", host, err)
		}
		select {
		case slots <- struct{}{}:
			go func() {
				defer func() { <-slots }()
				f.forward(ctx, c, host)
			}()
		default:
			log.Printf("egress: at the %d connection limit, refusing one for %s", f.capacity, host)
			_ = c.Close()
		}
	}
}

func (f *Forwarder) forward(ctx context.Context, c net.Conn, host string) {
	defer c.Close()
	ctx, cancel := context.WithTimeout(ctx, dialBudget)
	up, err := f.connect(ctx, host)
	cancel()
	if err != nil {
		log.Printf("egress: %s: %v", host, err)
		return
	}
	defer up.Close()
	var wg sync.WaitGroup
	wg.Go(func() { f.pipe(up, c) })
	f.pipe(c, up)
	wg.Wait()
}

// connect resolves on every connection, because S3's answers change constantly,
// and tries each address once in random order.
func (f *Forwarder) connect(ctx context.Context, host string) (net.Conn, error) {
	ips, err := f.lookup(ctx, host)
	if err != nil {
		return nil, err
	}
	if len(ips) == 0 {
		return nil, errors.New("no addresses")
	}
	var errs []error
	for _, i := range rand.Perm(len(ips)) {
		c, err := f.dial(ctx, net.JoinHostPort(ips[i].String(), s3Port))
		if err == nil {
			return c, nil
		}
		errs = append(errs, err)
	}
	return nil, errors.Join(errs...)
}

// pipe copies one direction, then passes on the end of the stream so the other
// direction can finish. Any other failure ends both.
func (f *Forwarder) pipe(dst, src net.Conn) {
	buf := make([]byte, maxBufferSize)
	for {
		_ = src.SetReadDeadline(time.Now().Add(f.idle))
		n, err := src.Read(buf)
		if n > 0 {
			_ = dst.SetWriteDeadline(time.Now().Add(f.idle))
			if _, werr := dst.Write(buf[:n]); werr != nil {
				_ = src.Close()
				_ = dst.Close()
				return
			}
		}
		if errors.Is(err, io.EOF) {
			if w, ok := dst.(interface{ CloseWrite() error }); ok {
				_ = w.CloseWrite()
				return
			}
		}
		if err != nil {
			_ = src.Close()
			_ = dst.Close()
			return
		}
	}
}

// NewHTTPClient returns the S3 client's HTTP client. A request still names its
// bucket's real URL, so TLS verifies S3's certificate for that hostname. Only the
// TCP connection goes to the forwarder.
func NewHTTPClient(forwarder string, routes []Route) *http.Client {
	ports := make(map[string]string, len(routes))
	for _, r := range routes {
		ports[r.Host] = strconv.Itoa(r.Port)
	}
	d := net.Dialer{Timeout: forwarderDialTimeout}
	return &http.Client{
		Timeout: 30 * time.Second,
		Transport: &http.Transport{
			TLSHandshakeTimeout: 10 * time.Second,
			MaxIdleConnsPerHost: 16,
			IdleConnTimeout:     edgeIdleTimeout,
			DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				host, port, err := net.SplitHostPort(addr)
				if err != nil {
					return nil, err
				}
				route, ok := ports[host]
				if !ok || port != s3Port {
					return nil, fmt.Errorf("egress: no route to %s", addr)
				}
				return dialRetry(ctx, func() (net.Conn, error) {
					return d.DialContext(ctx, network, net.JoinHostPort(forwarder, route))
				})
			},
		},
	}
}

func dialRetry(ctx context.Context, dial func() (net.Conn, error)) (net.Conn, error) {
	c, err := dial()
	for _, wait := range forwarderRetries {
		if err == nil {
			return c, nil
		}
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(wait):
		}
		c, err = dial()
	}
	return c, err
}
