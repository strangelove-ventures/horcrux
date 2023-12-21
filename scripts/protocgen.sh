#!/usr/bin/env bash

set -eox pipefail

echo "Generating proto code"

proto_dirs=$(find ./proto -path -prune -o -name '*.proto' -print0 | xargs -0 -n1 dirname | sort | uniq)
for dir in $proto_dirs; do
  for file in $(find "${dir}" -maxdepth 1 -name '*.proto'); do
      buf generate $file --template proto/buf.gen.yaml
  done
done

cp -r github.com/strangelove-ventures/horcrux/v3/signer ./
rm -rf github.com
