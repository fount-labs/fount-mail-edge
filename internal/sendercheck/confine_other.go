//go:build !linux

package sendercheck

// confinements is empty-handed off Linux. The edge runs on Linux; elsewhere
// (tests on a laptop) the child isn't confined.
func confinements() []confinement {
	return []confinement{{"none", nil}}
}
