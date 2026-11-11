package main

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strings"
	"syscall"
)

// The edge asks for exactly these (internal/send): SMTP to an MX on 25, and
// HTTPS on 443 to its two DNS-over-HTTPS resolvers and to MTA-STS policy hosts.
var dohHosts = map[string]bool{
	"dns.google":         true,
	"cloudflare-dns.com": true,
}

var (
	errPolicy  = errors.New("destination not allowed")
	errAddress = errors.New("destination resolves to a non-public address")
)

// target is a CONNECT authority that passed the name rules. Exactly one of name
// and ip is set.
type target struct {
	name string
	ip   netip.Addr
	port uint16
}

// checkTarget applies the name rules to a CONNECT authority, before any lookup.
func checkTarget(authority string) (target, error) {
	host, port, err := net.SplitHostPort(authority)
	if err != nil {
		return target{}, fmt.Errorf("%w: %v", errPolicy, err)
	}
	if strings.HasPrefix(authority, "[") {
		if ip, err := netip.ParseAddr(host); err != nil || !ip.Is6() {
			return target{}, errPolicy // brackets are for IPv6 literals only
		}
	}
	switch port {
	case "25":
		if ip, err := netip.ParseAddr(host); err == nil {
			if ip.Zone() != "" || !publicAddr(ip) {
				return target{}, errAddress
			}
			return target{ip: ip.Unmap(), port: 25}, nil
		}
		name, ok := dnsName(host)
		if !ok {
			return target{}, errPolicy
		}
		return target{name: name, port: 25}, nil
	case "443":
		name, ok := dnsName(host)
		if !ok {
			return target{}, errPolicy
		}
		if dohHosts[name] {
			return target{name: name, port: 443}, nil
		}
		if rest, found := strings.CutPrefix(name, "mta-sts."); found && rest != "" {
			return target{name: name, port: 443}, nil
		}
		return target{}, errPolicy
	}
	return target{}, errPolicy
}

// dnsName lowercases a hostname and drops one trailing dot. It refuses IP
// literals and anything that isn't letters, digits and hyphens in dotted labels.
func dnsName(h string) (string, bool) {
	h = strings.ToLower(strings.TrimSuffix(h, "."))
	if h == "" || len(h) > 253 {
		return "", false
	}
	if _, err := netip.ParseAddr(h); err == nil {
		return "", false
	}
	for _, label := range strings.Split(h, ".") {
		if label == "" || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return "", false
		}
		for i := 0; i < len(label); i++ {
			c := label[i]
			if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-') {
				return "", false
			}
		}
	}
	// An all-numeric last label is how some resolvers read IPv4 shorthand.
	last := h[strings.LastIndexByte(h, '.')+1:]
	if strings.Trim(last, "0123456789") == "" {
		return "", false
	}
	return h, true
}

// nonPublic lists every special-purpose range (RFC 6890 and its updates) that
// isn't reachable on the public internet, plus ranges that embed another
// address (NAT64, 6to4, Teredo) and so could smuggle a private one.
var nonPublic = func() []netip.Prefix {
	var out []netip.Prefix
	for _, s := range []string{
		"0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8", "169.254.0.0/16",
		"172.16.0.0/12", "192.0.0.0/24", "192.0.2.0/24", "192.88.99.0/24", "192.168.0.0/16",
		"198.18.0.0/15", "198.51.100.0/24", "203.0.113.0/24", "224.0.0.0/4", "240.0.0.0/4",
		"64:ff9b::/96", "64:ff9b:1::/48", "2001::/23", "2001:db8::/32", "2002::/16", "3fff::/20",
	} {
		out = append(out, netip.MustParsePrefix(s))
	}
	return out
}()

var globalUnicast6 = netip.MustParsePrefix("2000::/3")

// publicAddr reports whether ip is a public unicast address. Loopback, private,
// link-local (which holds the EC2 metadata service at 169.254.169.254), the
// metadata service's IPv6 fd00:ec2::254, multicast and documentation ranges
// are all refused.
func publicAddr(ip netip.Addr) bool {
	ip = ip.Unmap()
	if !ip.IsValid() || ip.Zone() != "" {
		return false
	}
	if ip.Is6() && !globalUnicast6.Contains(ip) {
		return false
	}
	for _, p := range nonPublic {
		if p.Contains(ip) {
			return false
		}
	}
	return true
}

// checkDialed runs on the socket just before connect(2), so whatever address
// the dialer ended up with, a non-public one or another port never connects.
// It is the second check: the relay already dials only addresses it resolved
// and checked itself, so a DNS answer that changes between lookups (rebinding)
// has nothing to change.
func checkDialed(network, address string, _ syscall.RawConn) error {
	if network != "tcp4" && network != "tcp6" {
		return fmt.Errorf("relay dials tcp only, not %s", network)
	}
	ap, err := netip.ParseAddrPort(address)
	if err != nil {
		return err
	}
	if ap.Port() != 25 && ap.Port() != 443 {
		return errPolicy
	}
	if !publicAddr(ap.Addr()) {
		return errAddress
	}
	return nil
}
