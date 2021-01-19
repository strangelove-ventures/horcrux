#!/bin/bash

SIGNER_DATA=$HOME/.tmsigner
CHAINID=$2

# Ensure user understands what will be deleted
if [[ -d $SIGNER_DATA ]] && [[ ! "$1" == "skip" ]]; then
  read -p "$0 will delete \$HOME/.tmsigner folder. Do you wish to continue? (y/n): " -n 1 -r
  echo 
  if [[ ! $REPLY =~ ^[Yy]$ ]]; then
      exit 1
  fi
fi

if [ -z "$2" ]; then
  echo "Need to input chain-id..."
  exit 1
fi

rm -rf $SIGNER_DATA &> /dev/null
./build/tmsigner init signerchain
./build/tmsigner nodes add tcp://localhost:1235
