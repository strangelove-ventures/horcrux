#!/bin/sh
# USAGE: ./one-chain test-chain-id ./data 26657 26656

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
mv $n0cfgDir/priv_validator_key.json $HOME/.tmsigner/priv_validator_key.json
mv $n0dir/data/priv_validator_state.json $HOME/.tmsigner/data/${CHAINID}_priv_validator_state.json

# Start the akash instances
gaiad $home0 start --pruning=nothing > $CHAINDIR/$CHAINID.n0.log 2>&1 &
gaiad $home1 start --pruning=nothing > $CHAINDIR/$CHAINID.n1.log 2>&1 &