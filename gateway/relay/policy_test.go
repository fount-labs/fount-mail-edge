package main

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"testing"
)

func TestCheckTargetAllows(t *testing.T) {
	for in, want := range map[string]target{
		"mx.example.com:25":              {name: "mx.example.com", port: 25},
		"MX1.Example.COM.:25":            {name: "mx1.example.com", port: 25},
		"xn--bcher-kva.example:25":       {name: "xn--bcher-kva.example", port: 25},
		"8.8.8.8:25":                     {ip: netip.MustParseAddr("8.8.8.8"), port: 25},
		"[2607:f8b0:4004:c1b::1a]:25":    {ip: netip.MustParseAddr("2607:f8b0:4004:c1b::1a"), port: 25},
		"dns.google:443":                 {name: "dns.google", port: 443},
		"DNS.google.:443":                {name: "dns.google", port: 443},
		"cloudflare-dns.com:443":         {name: "cloudflare-dns.com", port: 443},
		"mta-sts.smithcpa.com:443":       {name: "mta-sts.smithcpa.com", port: 443},
		"mta-sts.mail.example.co.uk:443": {name: "mta-sts.mail.example.co.uk", port: 443},
	} {
		got, err := checkTarget(in)
		if err != nil || got != want {
			t.Errorf("checkTarget(%q) = %+v, %v; want %+v", in, got, err, want)
		}
	}
}

func TestCheckTargetRefuses(t *testing.T) {
	for _, in := range []string{
		// Other ports, and 443 to anything but the DoH and MTA-STS hosts.
		"mx.example.com:587", "mx.example.com:465", "dns.google:80", "dns.google:853",
		"example.com:443", "smtp.gmail.com:443", "mta-sts:443", "mta-sts.:443",
		"xmta-sts.example.com:443", "dns.google.evil.com:443", "8.8.8.8:443",
		"[2001:4860:4860::8888]:443", "mx.example.com:0", "mx.example.com:025",
		// IP literals that aren't public.
		"127.0.0.1:25", "[::1]:25", "10.1.2.3:25", "172.31.0.2:25", "192.168.1.1:25",
		"169.254.169.254:25", "[fd00:ec2::254]:25", "[::ffff:127.0.0.1]:25",
		"[::ffff:169.254.169.254]:25", "[fe80::1%eth0]:25", "0.0.0.0:25", "[::]:25",
		"100.64.0.1:25", "255.255.255.255:25", "[64:ff9b::a00:1]:25", "[2002:a00:1::]:25",
		// Names that aren't plain hostnames, or read as IPv4 shorthand.
		"mx.example.com", "evil.com/x:25", "a b.com:25", "under_score.example:25",
		"-bad.example:25", "bad-.example:25", "a..b:25", "127.1:25", "2130706433:25",
		"0x7f.0.0.1:25", ":25", "[mx.example.com]:25",
	} {
		if got, err := checkTarget(in); err == nil {
			t.Errorf("checkTarget(%q) = %+v, want refused", in, got)
		}
	}
}

func TestPublicAddr(t *testing.T) {
	public := []string{"8.8.8.8", "1.1.1.1", "93.184.215.14", "2607:f8b0:4004:c1b::1a", "2a00:1450:4001:82a::200e", "::ffff:8.8.8.8"}
	private := []string{
		"127.0.0.1", "127.255.255.254", "::1", "10.0.0.1", "172.16.0.1", "172.31.255.255",
		"192.168.0.1", "169.254.169.254", "169.254.169.253", "fd00:ec2::254", "fe80::1",
		"fc00::1", "100.64.0.1", "0.0.0.0", "::", "224.0.0.1", "ff02::1", "240.0.0.1",
		"255.255.255.255", "192.0.2.1", "198.51.100.1", "203.0.113.1", "198.18.0.1",
		"192.0.0.8", "2001:db8::1", "64:ff9b::7f00:1", "2002:7f00:1::", "2001::1",
		"::ffff:10.0.0.1", "::127.0.0.1", "3fff::1",
	}
	for _, s := range public {
		if !publicAddr(netip.MustParseAddr(s)) {
			t.Errorf("publicAddr(%s) = false", s)
		}
	}
	for _, s := range private {
		if publicAddr(netip.MustParseAddr(s)) {
			t.Errorf("publicAddr(%s) = true", s)
		}
	}
}

// The socket-level check refuses what the name check would, whatever reached
// the dialer, so even a bug before it can't connect inside.
func TestCheckDialed(t *testing.T) {
	for addr, want := range map[string]error{
		"8.8.8.8:25":           nil,
		"[2607:f8b0::1]:443":   nil,
		"8.8.8.8:22":           errPolicy,
		"127.0.0.1:25":         errAddress,
		"169.254.169.254:443":  errAddress,
		"[fd00:ec2::254]:443":  errAddress,
		"[::ffff:10.0.0.1]:25": errAddress,
	} {
		network := "tcp4"
		if netip.MustParseAddrPort(addr).Addr().Is6() {
			network = "tcp6"
		}
		if err := checkDialed(network, addr, nil); !errors.Is(err, want) {
			t.Errorf("checkDialed(%s) = %v, want %v", addr, err, want)
		}
	}
	if checkDialed("udp4", "8.8.8.8:25", nil) == nil {
		t.Error("checkDialed allowed udp")
	}
}

// The relay's own dialer refuses a loopback listener on an allowed port.
func TestDefaultDialRefusesLoopback(t *testing.T) {
	r := &Relay{}
	for _, ap := range []string{"127.0.0.1:25", "127.0.0.1:443", "169.254.169.254:443"} {
		c, err := r.dial(context.Background(), netip.MustParseAddrPort(ap))
		if err == nil {
			c.Close()
			t.Fatalf("dialed %s", ap)
		}
		var op *net.OpError
		if !errors.As(err, &op) || !errors.Is(err, errAddress) {
			t.Errorf("dial %s: %v, want the socket check's refusal", ap, err)
		}
	}
}
