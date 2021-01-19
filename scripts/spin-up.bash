#!/bin/sh
# USAGE: ./one-chain test-chain-id ./data

CHAINID=$1
CHAINDIR=$2

if [ -z "$1" ]; then
  echo "Need to input chain id..."
  exit 1
fi

if [ -z "$2" ]; then
  echo "Need to input directory to create files in..."
  exit 1
fi

echo "Creating gaiad instance with home=$CHAINDIR chain-id=$CHAINID..."
# Build genesis file incl account for passed address
coins="100000000000stake,100000000000samoleans"

# Have different home folders for each node
n0dir="$CHAINDIR/$CHAINID/n0"
n1dir="$CHAINDIR/$CHAINID/n1"
home0="--home $n0dir"
home1="--home $n1dir"
n0cfgDir="$n0dir/config"
n1cfgDir="$n1dir/config"
n0cfg="$n0cfgDir/config.toml"
n1cfg="$n1cfgDir/config.toml"
kbt="--keyring-backend="test""

# Initialize the 2 home directories
gaiad $home0 --chain-id $CHAINID init n0 #&>/dev/null
gaiad $home1 --chain-id $CHAINID init n1 #&>/dev/null

# Add some keys for funds
gaiad $home0 keys add validator $kbt #&>/dev/null
gaiad $home0 keys add extra $kbt #&>/dev/null

# Add addresses to genesis
gaiad $home0 add-genesis-account $(gaiad $home0 keys $kbt show validator -a) $coins #&>/dev/null
gaiad $home0 add-genesis-account $(gaiad $home0 keys $kbt show extra -a) $coins #&>/dev/null

# Finalize genesis on n0 node
gaiad $home0 gentx validator 100000000000stake --home $n0dir $kbt --chain-id $CHAINID #&>/dev/null
gaiad $home0 collect-gentxs #&>/dev/null

# Copy genesis over to n1
cp $n0cfgDir/genesis.json $n1cfgDir/genesis.json

# Set proper defaults and change ports on n0
sed -i '' 's/timeout_commit = "5s"/timeout_commit = "1s"/g' $n0cfg
sed -i '' 's/timeout_propose = "3s"/timeout_propose = "1s"/g' $n0cfg
sed -i '' 's#priv_validator_laddr = ""#priv_validator_laddr = "tcp://0.0.0.0:1234"#g' $n0cfg

# Set proper defaults and change ports on n1
sed -i '' 's#"tcp://127.0.0.1:26657"#"tcp://0.0.0.0:26667"#g' $n1cfg
sed -i '' 's#"tcp://0.0.0.0:26656"#"tcp://0.0.0.0:26666"#g' $n1cfg
sed -i '' 's#"0.0.0.0:9090"#"0.0.0.0:9091"#g' $n1cfgDir/app.toml
sed -i '' 's#"localhost:6060"#"localhost:6061"#g' $n1cfg
sed -i '' 's/timeout_commit = "5s"/timeout_commit = "1s"/g' $n1cfg
sed -i '' 's/timeout_propose = "3s"/timeout_propose = "1s"/g' $n1cfg
sed -i '' 's#priv_validator_laddr = ""#priv_validator_laddr = "tcp://0.0.0.0:1235"#g' $n1cfg

# Set peers for both nodes
peer0="$(gaiad $home0 tendermint show-node-id)@127.0.0.1:26656"
peer1="$(gaiad $home1 tendermint show-node-id)@127.0.0.1:26666"
sed -i '' 's#persistent_peers = ""#persistent_peers = "'$peer1'"#g' $n0cfg
sed -i '' 's#persistent_peers = ""#persistent_peers = "'$peer0'"#g' $n1cfg

# Copy priv validator over from node that signed gentx to the signer
mv $n0cfgDir/priv_validator_key.json $CHAINDIR/priv_validator_key.json
cd $CHAINDIR
go run ../cmd/key2shares/main.go --total 3 --threshold 2 ./priv_validator_key.json
mkdir signer1 signer2 signer3
cp ./private_share_1.json ./signer1/priv-key-shard.json
cp ../scripts/cosigner1.toml ./signer1/config.toml
cp ../scripts/state.json ./signer1/test-chain-id_share_sign_state.json
cp ./private_share_2.json ./signer2/priv-key-shard.json
cp ../scripts/cosigner2.toml ./signer2/config.toml
cp ../scripts/state.json ./signer2/test-chain-id_share_sign_state.json
cp ./private_share_3.json ./signer3/priv-key-shard.json
cp ../scripts/cosigner3.toml ./signer3/config.toml
cp ../scripts/state.json ./signer3/test-chain-id_share_sign_state.json
cd ..

# Start the gaia instances
go run cmd/signer/main.go --config $CHAINDIR/signer1/config.toml > $CHAINDIR/signer1.log 2>&1 &
go run cmd/signer/main.go --config $CHAINDIR/signer2/config.toml > $CHAINDIR/signer2.log 2>&1 &
go run cmd/signer/main.go --config $CHAINDIR/signer3/config.toml > $CHAINDIR/signer3.log 2>&1 &
gaiad $home0 start --pruning=nothing > $CHAINDIR/$CHAINID.n0.log 2>&1 &
gaiad $home1 start --pruning=nothing > $CHAINDIR/$CHAINID.n1.log 2>&1 &