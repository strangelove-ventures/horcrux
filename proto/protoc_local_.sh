#!/usr/bin/env bash

set -eox pipefail

echo "Generating proto code"

# OUT_DIR=$(pwd)/proto
# echo $OUT_DIR
# protoc --go_out=$(pwd) strangelove/horcrux/cosigner.proto
protoc -I=. --go_out=./ --go-grpc_out=./ --go-grpc_opt=paths=source_relative --go_opt=paths=source_relative strangelove/proto/cosigner.proto
protoc -I=. --go_out=./ --go-grpc_out=./ --go-grpc_opt=paths=source_relative --go_opt=paths=source_relative strangelove/proto/node.proto
protoc -I=. --go_out=./ --go-grpc_out=./ --go-grpc_opt=paths=source_relative --go_opt=paths=source_relative strangelove/proto/connector.proto

#protoc -I=. --go-grpc_out=./ --go-grpc_opt=paths=source_relative strangelove/horcrux/connector.proto
# protoc -I=. --go_out=strangelove/proto --go_opt=paths=source_relative strangelove/horcrux/node.proto
