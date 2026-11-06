module github.com/fount-labs/fount-mail-edge

// Pinned for reproducible builds (see docs/BUILD.md and §17 of the design doc).
// The toolchain line pins the exact Go version CI and the Docker build use.
go 1.27.3

// Intentionally dependency-free: the edge uses only the Go standard library, so
// there is no go.sum and no third-party supply-chain surface to reproduce. HPKE
// storage (M2 step 4) and ACME (M2 step 3) will add vetted, digest-pinned deps.
