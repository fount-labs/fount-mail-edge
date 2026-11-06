# Reproducible, minimal image for the Fount Fleet mail edge (design §17).
#
# Goals: a bit-for-bit identical image digest on any machine, and a final image
# that contains only the static binary and CA roots (FROM scratch). The
# determinism flags that must match across runners live in scripts/build-image.sh;
# this Dockerfile is the recipe that script drives.
#
# TODO(before first release): pin BOTH the dockerfile frontend and the golang
# base image by digest, and pin the exact Go patch version to go.mod's. Resolve
# the digests deliberately (not :latest) and commit them; CI rebuilds on two
# runners and fails if the resulting image digests differ.

# syntax=docker/dockerfile:1.19@sha256:PLACEHOLDER_PIN_THE_FRONTEND_DIGEST

FROM golang:1.27.3-alpine@sha256:PLACEHOLDER_PIN_THE_GOLANG_BASE_DIGEST AS build
WORKDIR /src
# Stdlib-only: go.mod alone is the full dependency set (no go.sum).
COPY go.mod ./
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
