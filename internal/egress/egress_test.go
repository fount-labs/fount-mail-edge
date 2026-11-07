package egress

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

const bucket = "example.com" // httptest's certificate covers this name

func TestParseRoutes(t *testing.T) {
	got, err := ParseRoutes("9001=a.example, 9002=b.example")
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 || got[1] != (Route{9002, "b.example"}) {
		t.Fatalf("routes = %+v", got)
	}
	for _, bad := range []string{"", "a.example", "x=a.example", "80=a.example", "99999=a.example", "9001=", "9001=a.example:443", "9001=a.example,9001=b.example", "9001=a.example,9002=a.example"} {
		if _, err := ParseRoutes(bad); err == nil {
			t.Errorf("ParseRoutes(%q) accepted", bad)
		}
	}
}

// start runs f on loopback and returns the routes it listens on.
func start(t *testing.T, f *Forwarder, hosts ...string) {
	t.Helper()
	var listeners []net.Listener
	for _, h := range hosts {
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		listeners = append(listeners, ln)
		f.Routes = append(f.Routes, Route{ln.Addr().(*net.TCPAddr).Port, h})
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- f.serve(ctx, listeners) }()
	t.Cleanup(func() {
		cancel()
		if err := <-done; err != nil {
			t.Errorf("serve: %v", err)
		}
	})
}

func toAddr(addr string) func(context.Context, string) (net.Conn, error) {
	return func(ctx context.Context, _ string) (net.Conn, error) {
		var d net.Dialer
		return d.DialContext(ctx, "tcp", addr)
	}
}

func lookupOne(context.Context, string) ([]net.IP, error) {
	return []net.IP{net.IPv4(192, 0, 2, 1)}, nil
}

func trusting(t *testing.T, c *http.Client, srv *httptest.Server) *http.Client {
	t.Helper()
	c.Transport.(*http.Transport).TLSClientConfig = &tls.Config{RootCAs: srv.Client().Transport.(*http.Transport).TLSClientConfig.RootCAs}
	return c
}

// The edge's path: the request names the bucket, TCP goes to the forwarder, and
// TLS verifies the bucket's certificate on the far side.
func TestRequestReachesTheBucketThroughTheForwarder(t *testing.T) {
	var gotHost atomic.Value
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotHost.Store(r.Host)
		body, _ := io.ReadAll(r.Body)
		fmt.Fprintf(w, "stored %d", len(body))
	}))
	defer srv.Close()
	f := &Forwarder{lookup: lookupOne, dial: toAddr(srv.Listener.Addr().String())}
	start(t, f, bucket)
	c := trusting(t, NewHTTPClient("127.0.0.1", f.Routes), srv)

	body := strings.Repeat("x", 3<<20)
	res, err := c.Post("https://"+bucket+"/key", "text/plain", strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	got, _ := io.ReadAll(res.Body)
	if string(got) != fmt.Sprintf("stored %d", len(body)) {
		t.Fatalf("got %q", got)
	}
	if gotHost.Load() != bucket {
		t.Fatalf("Host = %v", gotHost.Load())
	}
}

// If the far side isn't really that bucket, the edge refuses it, whatever the
// forwarder connected to.
func TestEdgeVerifiesTheBucketCertificate(t *testing.T) {
	srv := httptest.NewTLSServer(http.NotFoundHandler())
	defer srv.Close()
	f := &Forwarder{lookup: lookupOne, dial: toAddr(srv.Listener.Addr().String())}
	start(t, f, "not-this-certificate.test")
	c := trusting(t, NewHTTPClient("127.0.0.1", f.Routes), srv)
	_, err := c.Get("https://not-this-certificate.test/")
	var hostErr x509.HostnameError
	if err == nil || !errors.As(err, &hostErr) {
		t.Fatalf("err = %v, want a certificate hostname error", err)
	}
}

func TestEdgeRefusesAnythingWithoutARoute(t *testing.T) {
	c := NewHTTPClient("127.0.0.1", []Route{{9, bucket}})
	for _, u := range []string{"https://elsewhere.test/", "https://" + bucket + ":8443/"} {
		_, err := c.Get(u)
		if err == nil || !strings.Contains(err.Error(), "no route") {
			t.Errorf("%s: err = %v", u, err)
		}
	}
}

func TestForwarderTriesEveryAddress(t *testing.T) {
	up := echoServer(t)
	var tried atomic.Int32
	f := &Forwarder{
		lookup: func(context.Context, string) ([]net.IP, error) {
			return []net.IP{net.IPv4(192, 0, 2, 1), net.IPv4(192, 0, 2, 2), net.IPv4(192, 0, 2, 3)}, nil
		},
		dial: func(ctx context.Context, addr string) (net.Conn, error) {
			if !strings.HasSuffix(addr, ":443") {
				t.Errorf("dialed %s", addr)
			}
			if !strings.HasPrefix(addr, "192.0.2.3:") {
				tried.Add(1)
				return nil, errors.New("timed out")
			}
			return toAddr(up)(ctx, addr)
		},
	}
	start(t, f, bucket)
	for range 20 {
		roundTrip(t, f.Routes[0].Port)
	}
	if tried.Load() == 0 {
		t.Fatal("never hit a failing address, so this proved nothing")
	}
}

func TestForwarderResolvesEveryConnection(t *testing.T) {
	up := echoServer(t)
	var lookups atomic.Int32
	f := &Forwarder{
		lookup: func(ctx context.Context, h string) ([]net.IP, error) {
			lookups.Add(1)
			return lookupOne(ctx, h)
		},
		dial: toAddr(up),
	}
	start(t, f, bucket)
	roundTrip(t, f.Routes[0].Port)
	roundTrip(t, f.Routes[0].Port)
	if n := lookups.Load(); n != 2 {
		t.Fatalf("lookups = %d", n)
	}
}

// A response can follow the end of a request, so one direction closing must not
// end the other.
func TestHalfCloseStillDeliversTheResponse(t *testing.T) {
	ln := listen(t)
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		got, _ := io.ReadAll(c)
		time.Sleep(50 * time.Millisecond)
		_, _ = c.Write([]byte("saw " + string(got)))
	}()
	f := &Forwarder{lookup: lookupOne, dial: toAddr(ln.Addr().String())}
	start(t, f, bucket)
	c := connectTo(t, f.Routes[0].Port)
	defer c.Close()
	_, _ = c.Write([]byte("request"))
	_ = c.(*net.TCPConn).CloseWrite()
	got, err := io.ReadAll(c)
	if err != nil || string(got) != "saw request" {
		t.Fatalf("got %q, %v", got, err)
	}
}

func TestConnectionLimitRefusesWithoutDialing(t *testing.T) {
	up := echoServer(t)
	var dials atomic.Int32
	f := &Forwarder{
		lookup:   lookupOne,
		capacity: 1,
		dial: func(ctx context.Context, addr string) (net.Conn, error) {
			dials.Add(1)
			return toAddr(up)(ctx, addr)
		},
	}
	start(t, f, bucket)
	held := connectTo(t, f.Routes[0].Port)
	defer held.Close()
	_, _ = held.Write([]byte("x"))
	if _, err := io.ReadFull(held, make([]byte, 1)); err != nil {
		t.Fatal(err)
	}
	over := connectTo(t, f.Routes[0].Port)
	defer over.Close()
	_ = over.SetReadDeadline(time.Now().Add(5 * time.Second))
	if _, err := over.Read(make([]byte, 1)); !errors.Is(err, io.EOF) && !isReset(err) {
		t.Fatalf("over-limit read err = %v", err)
	}
	if n := dials.Load(); n != 1 {
		t.Fatalf("dials = %d", n)
	}
}

func TestIdleConnectionsAreDropped(t *testing.T) {
	up := echoServer(t)
	f := &Forwarder{lookup: lookupOne, dial: toAddr(up), idle: 100 * time.Millisecond}
	start(t, f, bucket)
	c := connectTo(t, f.Routes[0].Port)
	defer c.Close()
	_ = c.SetReadDeadline(time.Now().Add(5 * time.Second))
	if _, err := c.Read(make([]byte, 1)); !errors.Is(err, io.EOF) && !isReset(err) {
		t.Fatalf("read err = %v", err)
	}
}

// The containers start in parallel, so the first S3 call can land before the
// forwarder listens. In the live probe, those were the only failures.
func TestEdgeWaitsForTheForwarderToStart(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("ok"))
	}))
	defer srv.Close()
	reserved := listen(t)
	port := reserved.Addr().(*net.TCPAddr).Port
	reserved.Close()

	c := trusting(t, NewHTTPClient("127.0.0.1", []Route{{port, bucket}}), srv)
	go func() {
		time.Sleep(400 * time.Millisecond)
		ln, err := net.Listen("tcp", "127.0.0.1:"+strconv.Itoa(port))
		if err != nil {
			t.Error(err)
			return
		}
		f := &Forwarder{Routes: []Route{{port, bucket}}, lookup: lookupOne, dial: toAddr(srv.Listener.Addr().String())}
		ctx, cancel := context.WithCancel(context.Background())
		t.Cleanup(cancel)
		_ = f.serve(ctx, []net.Listener{ln})
	}()
	res, err := c.Get("https://" + bucket + "/")
	if err != nil {
		t.Fatal(err)
	}
	res.Body.Close()
}

func TestServeNeedsRoutes(t *testing.T) {
	if err := (&Forwarder{}).Serve(context.Background()); err == nil {
		t.Fatal("served with no routes")
	}
}

func listen(t *testing.T) net.Listener {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	return ln
}

func echoServer(t *testing.T) string {
	t.Helper()
	ln := listen(t)
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				_, _ = io.Copy(c, c)
			}()
		}
	}()
	return ln.Addr().String()
}

func connectTo(t *testing.T, port int) net.Conn {
	t.Helper()
	c, err := net.DialTimeout("tcp", "127.0.0.1:"+strconv.Itoa(port), 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func roundTrip(t *testing.T, port int) {
	t.Helper()
	c := connectTo(t, port)
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := c.Write([]byte("ping")); err != nil {
		t.Fatal(err)
	}
	got := make([]byte, 4)
	if _, err := io.ReadFull(c, got); err != nil || string(got) != "ping" {
		t.Fatalf("got %q, %v", got, err)
	}
}

func isReset(err error) bool {
	return err != nil && strings.Contains(err.Error(), "connection reset")
}
