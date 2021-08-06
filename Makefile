all: build

build:
	@go build -o horcrux ./cmd/horcrux/...

install:
	@go install ./cmd/horcrux/...

build-linux:
	@GOOS=linux GOARCH=amd64 go build -o ./build/horcrux ./cmd/horcrux

test:
	@go test -v ./...

clean:
	rm -rf build

build-simd-docker:
	docker build -t jackzampolin/simd:v0.42.3 -f ./docker/simd/Dockerfile ./docker/simd/

build-horcrux-docker:
	docker build -t strangelove-ventures/horcrux:v0.1.0 -f ./docker/horcrux/Dockerfile .

.PHONY: all lint test race msan tools clean build