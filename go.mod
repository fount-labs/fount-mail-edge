module github.com/fount-labs/fount-mail-edge

// Pinned for reproducible builds (see docs/BUILD.md and §17 of the design doc).
// The toolchain line pins the exact Go version CI and the Docker build use.
go 1.27.3

// Intentionally free of third-party code: the edge uses only the Go standard
// library and Fount's own vault/wire module, which is standard-library only too.
// That module is vendored, so the build reads it from vendor/ and needs no
// network and no go.sum.
require github.com/fount-labs/fount-mail-vault/wire v0.0.0

// Until fount-mail-vault is published, this points at the sibling checkout.
// Replace it with a tagged version (wire/vX.Y.Z) when it is.
replace github.com/fount-labs/fount-mail-vault/wire => ../fount-mail-vault/wire
