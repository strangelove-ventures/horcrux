VERSION := $(shell echo $(shell git describe --tags) | sed 's/^v//')
COMMIT  := $(shell git log -1 --format='%H')

all: install

LD_FLAGS = -X github.com/strangelove-ventures/horcrux/cmd/horcrux/cmd.Version=$(VERSION) \
	-X github.com/strangelove-ventures/horcrux/cmd/horcrux/cmd.Commit=$(COMMIT)

BUILD_FLAGS := -ldflags '$(LD_FLAGS)'

build:
	@go build -mod readonly $(BUILD_FLAGS) -o build/ ./cmd/horcrux/...

install:
	@go install -mod readonly $(BUILD_FLAGS) ./cmd/horcrux/...

build-linux:
	@GOOS=linux GOARCH=amd64 go build --mod readonly $(BUILD_FLAGS) -o ./build/horcrux ./cmd/horcrux

test:
	@go test -timeout 20m -mod readonly -v ./...

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

signer-proto:
	docker run \
	  --rm \
	  -u $(shell id -u ${USER}):$(shell id -g ${USER}) \
		--mount type=bind,source=$(mkfile_dir)/signer/proto,target=/horcrux/signer/proto \
		--entrypoint protoc \
		namely/protoc-all \
		--go_out=/horcrux \
		--go_opt=paths=source_relative \
		--go-grpc_out=/horcrux \
		--go-grpc_opt=paths=source_relative \
		--proto_path /horcrux \
		$(shell find $(mkfile_dir) -name *.proto -printf "%P\n")

.PHONY: all lint test race msan tools clean build