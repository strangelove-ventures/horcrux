all: build

build: build/signer

build/signer: cmd/signer/main.go $(wildcard internal/**/*.go)
	CGO_ENABLED=0 go build -o ./build/signer ${gobuild_flags} ./cmd/signer

install:
	go install ./cmd/horcrux/...

build-linux:
	GOOS=linux GOARCH=amd64 go build -o ./build/horcrux ./cmd/horcrux

test:
	@docker network prune
	@go test -v ./testing/...

tools:
	@go install golang.org/x/lint/golint

clean:
	rm -rf build

.PHONY: all lint test race msan tools clean build

build-simd-docker:
	docker build -t jackzampolin/simd:v0.42.3 -f ./docker/simd/Dockerfile ./docker/simd/

build-horcrux-docker:
	docker build -t strangelove-ventures/horcrux:v0.1.0 -f ./docker/horcrux/Dockerfile .