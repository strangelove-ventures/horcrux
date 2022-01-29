FROM golang:1.16-alpine AS build-env
ARG VERSION
ENV PACKAGES curl make git libc-dev bash gcc linux-headers eudev-dev

RUN apk add --no-cache $PACKAGES

WORKDIR /go/src/github.com/cosmos

RUN git clone https://github.com/cosmos/cosmos-sdk.git

WORKDIR /go/src/github.com/cosmos/cosmos-sdk

# TODO: parameterize and pull this version from the go.mod when running in makefile
RUN git checkout ${VERSION} && make build-linux

FROM alpine:edge

RUN apk add --no-cache ca-certificates
WORKDIR /root

# Copy over binaries from the build-env
COPY --from=build-env /go/src/github.com/cosmos/cosmos-sdk/build/simd /usr/bin/simd

EXPOSE 26656 26657 1317 9090 1234

# Run simd by default, omit entrypoint to ease using container with simcli
CMD ["simd"]
