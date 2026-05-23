# Device-side image. Carries ONLY hwinfo + verifier binaries and the
# Ed25519 public key. The private key MUST NOT be embedded here.
#
# Architecture: ARM64 by default (GB10 is Grace Blackwell). Override
# with --build-arg GOARCH=amd64 for x86_64.

ARG GOARCH=arm64

FROM --platform=$BUILDPLATFORM golang:1.24-alpine AS builder
ARG GOARCH
WORKDIR /src

COPY go.mod go.sum ./
RUN go mod download

COPY internal ./internal
COPY cmd ./cmd

ENV CGO_ENABLED=0
ENV GOOS=linux
ENV GOARCH=${GOARCH}
RUN go build -trimpath -ldflags="-s -w" -o /out/hwinfo   ./cmd/hwinfo
RUN go build -trimpath -ldflags="-s -w" -o /out/verifier ./cmd/verifier

# Final image: debian-slim has glibc + ldconfig, which the
# nvidia-container-toolkit needs in order to inject `nvidia-smi` and
# `libnvidia-ml.so.*` at container startup. Distroless-static does not
# work here because it has no dynamic linker.
#
# We still keep the surface area small: only ca-certificates is added
# on top of debian-slim; the two Go binaries are statically linked.
FROM debian:12-slim
RUN apt-get update \
 && apt-get install -y --no-install-recommends ca-certificates \
 && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY --from=builder /out/hwinfo   /app/hwinfo
COPY --from=builder /out/verifier /app/verifier

# NVIDIA Container Toolkit reads these. `utility` is the capability
# that brings in `nvidia-smi`; `compute` is only needed if you also
# want CUDA runtime libs (we don't).
ENV NVIDIA_VISIBLE_DEVICES=all \
    NVIDIA_DRIVER_CAPABILITIES=utility

# Default to running the verifier; operators can override to /app/hwinfo
# when collecting a fresh hardware.json.
ENTRYPOINT ["/app/verifier"]
