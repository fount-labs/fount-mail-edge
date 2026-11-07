# syntax=docker/dockerfile:1.19@sha256:b6afd42430b15f2d2a4c5a02b919e98a525b785b1aaff16747d2f623364e39b6
# Reproducible, minimal image for the Fount Fleet mail edge (design §17).
#
# Goals: a bit-for-bit identical image digest on any machine, and a final image
# that contains only the static binary and CA roots (FROM scratch). The
# determinism flags that must match across runners live in scripts/build-image.sh;
# this Dockerfile is the recipe that script drives.
#
# BuildKit reads the syntax line only at the very top of the file.
# Bump the frontend, base image, and go.mod's Go version on purpose, together.

FROM golang:1.27.3-alpine@sha256:fa3d596898d9f126af7c01d14ee7597bab3f39cccf392ef36b69fe77cd681f18 AS build
WORKDIR /src
# No third-party code: go.mod plus the vendored vault/wire module is the full
# dependency set, so the build needs no network and no go.sum.
COPY go.mod ./
COPY vendor ./vendor
COPY cmd ./cmd
COPY internal ./internal
ENV CGO_ENABLED=0 GOFLAGS=-trimpath GOTOOLCHAIN=local
RUN go build -trimpath -buildvcs=false -ldflags "-s -w -buildid=" -o /edge ./cmd/edge

FROM scratch
COPY --from=build /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
COPY --from=build /edge /edge
# smtp(tunnel) · device-api(tunnel) · acme-challenge(tunnel) · shim health
EXPOSE 2525 8443 8088 8080
ENTRYPOINT ["/edge"]
