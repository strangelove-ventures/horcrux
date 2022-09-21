FROM --platform=$BUILDPLATFORM golang:1.19.1-alpine3.16 AS build-env

ENV PACKAGES make git

RUN apk add --no-cache $PACKAGES

WORKDIR /go/src/github.com/strangelove-ventures/horcrux

ADD . .

ARG TARGETARCH
ARG TARGETOS

RUN export GOOS=${TARGETOS} GOARCH=${TARGETARCH} && make build

FROM alpine:edge

RUN apk add --no-cache ca-certificates

WORKDIR /root

COPY --from=build-env /go/src/github.com/strangelove-ventures/horcrux/build/horcrux  /usr/bin/horcrux

CMD ["horcrux"]
