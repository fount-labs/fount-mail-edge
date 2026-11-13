package acme

import (
	"crypto/rand"
	"slices"
	"strings"
)

// A boot name is a random hostname under the boot domain that each boot adds to
// its certificate (design §6). Every boot has a new mail-tls key and so needs a new
// certificate, and Let's Encrypt allows 5 a week for the same set of names. A name
// no other boot used makes every set new. The limit of 50 a week for the
// registered domain still applies. A wildcard A record for the boot domain points
// at the gateways, so HTTP-01 reaches the edge for any boot name.

// bootLabelLen is the length of rand.Text: 128 bits in base32.
const bootLabelLen = 26

// WithBootName returns hostnames plus a new boot name under domain, or hostnames
// alone when domain is empty.
func WithBootName(hostnames []string, domain string) []string {
	out := slices.Clone(hostnames)
	if domain == "" {
		return out
	}
	return append(out, strings.ToLower(rand.Text())+"."+domain)
}

// IsBootName reports whether name is one label of the form WithBootName makes,
// directly under domain.
func IsBootName(name, domain string) bool {
	label, rest, ok := strings.Cut(name, ".")
	if !ok || domain == "" || rest != domain || len(label) != bootLabelLen {
		return false
	}
	for _, c := range label {
		if !(c >= 'a' && c <= 'z' || c >= '2' && c <= '7') {
			return false
		}
	}
	return true
}
