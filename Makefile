golangci_lint_cmd=golangci-lint
golangci_version=v1.57.2
gofumpt_cmd=gofumpt
gofumpt_version=v0.6.0

VERSION := $(shell echo $(shell git describe --tags) | sed 's/^v//')
COMMIT  := $(shell git log -1 --format='%H')

default: help

.PHONY: help
## help: Prints this help message
help: Makefile
	@echo
	@echo "Available make commands:"
	@echo
	@sed -n 's/^##//p' $< | column -t -s ':' |  sed -e 's/^/ /'
	@echo


all: install

LD_FLAGS = -X github.com/strangelove-ventures/horcrux/v3/cmd/horcrux/cmd.Version=$(VERSION) \
	-X github.com/strangelove-ventures/horcrux/v3/cmd/horcrux/cmd.Commit=$(COMMIT)

LD_FLAGS += $(LDFLAGS)
LD_FLAGS := $(strip $(LD_FLAGS))

BUILD_FLAGS := -ldflags '$(LD_FLAGS)'

build:
	@go build -mod readonly $(BUILD_FLAGS) -o build/ ./cmd/horcrux/...

install:
	@go install -mod readonly $(BUILD_FLAGS) ./cmd/horcrux/...

build-linux:
	@GOOS=linux GOARCH=amd64 go build --mod readonly $(BUILD_FLAGS) -o ./build/horcrux ./cmd/horcrux

test:
	@go test -race -timeout 30m -mod readonly -v ./...

test-short:
	@go test -mod readonly -run TestDownedSigners2of3 -v ./... 

test-signer-short:
	@go test -mod readonly -run TestThresholdValidator2of3 -v ./... 

clean:
	rm -rf build

build-horcrux-docker:
	docker build -t strangelove-ventures/horcrux:$(VERSION) -f ./docker/horcrux/Dockerfile .

mkfile_path := $(abspath $(lastword $(MAKEFILE_LIST)))
mkfile_dir := $(dir $(mkfile_path))

DOCKER := $(shell which docker)
protoVer=0.11.2
protoImageName=ghcr.io/cosmos/proto-builder:$(protoVer)
protoImage=$(DOCKER) run --rm -v $(CURDIR):/workspace --workdir /workspace $(protoImageName)

proto-all: proto-format proto-lint proto-gen

proto-gen:
	@echo "Generating Protobuf files"
	@$(protoImage) sh ./scripts/protocgen.sh

proto-format:
	@$(protoImage) find ./ -name "*.proto" -exec clang-format -i {} \;

proto-lint:
	@$(protoImage) buf lint --error-format=json


.PHONY: all lint test race msan tools clean build

.PHONY: lint
## lint: Lint the repository
lint:
	@echo "--> Running linter"
	@if ! $(golangci_lint_cmd) --version 2>/dev/null | grep -q $(golangci_version); then \
        go install github.com/golangci/golangci-lint/cmd/golangci-lint@$(golangci_version); \
  fi
	      @$(golangci_lint_cmd) run ./... --timeout 15m

.PHONY: lint-fix
## lint-fix: Lint the repository and fix warnings (if applicable)
lint-fix:
	@echo "--> Running linter and fixing issues"
	@if ! $(golangci_lint_cmd) --version 2>/dev/null | grep -q $(golangci_version); then \
		go install github.com/golangci/golangci-lint/cmd/golangci-lint@$(golangci_version); \
	fi
	@$(golangci_lint_cmd) run ./... --fix --timeout 15m

.PHONY: gofumpt
## gofumpt: Format the code with gofumpt
gofumpt:
	@echo "--> Running gofumpt"
	@if ! $(gofumpt_cmd) -version 2>/dev/null | grep -q $(gofumpt_version); then \
		go install mvdan.cc/gofumpt@$(gofumpt_version); \
	fi
	@gofumpt -l -w .