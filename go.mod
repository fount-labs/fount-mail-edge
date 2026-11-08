module github.com/fount-labs/fount-mail-edge

// Pinned for reproducible builds (see docs/BUILD.md).
// The toolchain line pins the exact Go version CI and the Docker build use.
go 1.27.3

// Intentionally free of third-party code: the edge uses only the Go standard
// library and Fount's own vault/wire module, which is standard-library only too.
// That module is vendored, so the build reads it from vendor/ and needs no
// network and no go.sum.
require github.com/fount-labs/fount-mail-vault/wire v0.0.0

// The wire module has no tag yet, so this points at a sibling checkout of
// github.com/fount-labs/fount-mail-vault, used only by `go mod vendor`. The build
// reads vendor/. Once wire/vX.Y.Z is tagged, require that and drop the replace.
replace github.com/fount-labs/fount-mail-vault/wire => ../fount-mail-vault/wire
