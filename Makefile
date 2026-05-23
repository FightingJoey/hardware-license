.PHONY: all go-build issuer issuer-device licensedb hwinfo verifier device-build node-build node-test test clean deps docker

GO     := go
NODE   := node
BUILD  := build

# Linux target for hwinfo / verifier (device-side) and the docker image.
# Default is GB10 = linux/arm64; override on the command line, e.g.:
#   make hwinfo TARGET_ARCH=amd64
#   make docker TARGET_ARCH=amd64
TARGET_OS   ?= linux
TARGET_ARCH ?= arm64

all: go-build node-build

# --- Go ---------------------------------------------------------------------

# `issuer` runs on the operator's internal-network signing host, which
# may be macOS / Linux / Windows. We produce a native binary so the
# operator does not need a Linux VM just to sign a license.
issuer:
	@mkdir -p $(BUILD)
	$(GO) build -trimpath -ldflags="-s -w" -o $(BUILD)/issuer ./cmd/issuer

licensedb:
	@mkdir -p $(BUILD)
	$(GO) build -trimpath -ldflags="-s -w" -o $(BUILD)/licensedb ./cmd/licensedb

# Cross-compiled issuer for on-device signing (linux/arm64 by default).
issuer-device:
	@mkdir -p $(BUILD)
	GOOS=$(TARGET_OS) GOARCH=$(TARGET_ARCH) CGO_ENABLED=0 \
	  $(GO) build -trimpath -ldflags="-s -w" -o $(BUILD)/issuer-device ./cmd/issuer

# `hwinfo` and `verifier` run on the licensed device, always Linux. We
# cross-compile so that running `make` on a macOS developer machine
# still produces ELF binaries you can scp directly to the device.
hwinfo:
	@mkdir -p $(BUILD)
	GOOS=$(TARGET_OS) GOARCH=$(TARGET_ARCH) CGO_ENABLED=0 \
	  $(GO) build -trimpath -ldflags="-s -w" -o $(BUILD)/hwinfo ./cmd/hwinfo

verifier:
	@mkdir -p $(BUILD)
	GOOS=$(TARGET_OS) GOARCH=$(TARGET_ARCH) CGO_ENABLED=0 \
	  $(GO) build -trimpath -ldflags="-s -w" -o $(BUILD)/verifier ./cmd/verifier

device-build: hwinfo verifier issuer-device

go-build: issuer licensedb device-build

deps:
	$(GO) mod download

# --- Node -------------------------------------------------------------------

node-build:
	cd verifier-node && npm install --no-audit --no-fund && npx tsc -p .

# The interop test executes the issuer locally, so it needs the native
# host-side binary, not the Linux device binaries.
node-test: issuer node-build
	cd verifier-node && $(NODE) --test test/cross.test.js

test: node-test

# --- Docker -----------------------------------------------------------------

IMAGE ?= devqiaoyu/hw-license:1.0.0

docker:
	docker buildx build --platform $(TARGET_OS)/$(TARGET_ARCH) \
		--build-arg GOARCH=$(TARGET_ARCH) \
		-t $(IMAGE) --load .

# --- Housekeeping -----------------------------------------------------------

clean:
	rm -rf $(BUILD)
	rm -rf verifier-node/dist verifier-node/node_modules
