
VERSION := $(shell echo $(shell git describe --tags) | sed 's/^v//')
SDKVERSION := $(shell go list -m -u -f '{{.Version}}' github.com/cosmos/cosmos-sdk)
TMVERSION := $(shell go list -m -u -f '{{.Version}}' github.com/tendermint/tendermint)
COMMIT  := $(shell git log -1 --format='%H')

all: install

LD_FLAGS = -X github.com/strangelove-ventures/horcrux/version.Version=$(VERSION) \
	-X github.com/strangelove-ventures/horcrux/version.Commit=$(COMMIT) \
	-X github.com/strangelove-ventures/horcrux/version.SDKVersion=$(SDKVERSION) \
	-X github.com/strangelove-ventures/horcrux/version.TMVersion=$(TMVERSION)

BUILD_FLAGS := -ldflags '$(LD_FLAGS)'

build:
	@go build -mod readonly $(BUILD_FLAGS) -o build/ ./cmd/horcrux/...

install:
	@go install -mod readonly $(BUILD_FLAGS) ./cmd/horcrux/...

build-linux:
	@GOOS=linux GOARCH=amd64 go build --mod readonly $(BUILD_FLAGS) -o ./build/horcrux ./cmd/horcrux

test:
	@go test -mod readonly -v ./...

clean:
	rm -rf build

build-simd-docker:
	docker build -t jackzampolin/simd:$(SDKVERSION) -f ./docker/simd/Dockerfile ./docker/simd/

build-horcrux-docker:
	docker build -t strangelove-ventures/horcrux:$(VERSION) -f ./docker/horcrux/Dockerfile .

.PHONY: all lint test race msan tools clean build