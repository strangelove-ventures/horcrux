#!/bin/sh
# USAGE: ./one-chain

CHAINID=test-chain-id
CHAINDIR=./data	
HORCRUX=../build/horcrux

function setConfigHorcrux() {
    cfgdir=$1
    rpc=$2
    p2p=$3
    grpc=$4
    grpcweb=$5
    profile=$6
    privval=$7
    sed -i '' "s#127.0.0.1:26657#0.0.0.0:$rpc#g" $cfgdir/config.toml	
    sed -i '' "s#0.0.0.0:26656#0.0.0.0:$p2p#g" $cfgdir/config.toml	
    sed -i '' "s#0.0.0.0:9090#0.0.0.0:$grpc#g" $cfgdir/app.toml
    sed -i '' "s#0.0.0.0:9091#0.0.0.0:$grpcweb#g" $cfgdir/app.toml
    sed -i '' "s#localhost:6060#localhost:$profile#g" $cfgdir/config.toml	
    sed -i '' 's/timeout_commit = "5s"/timeout_commit = "3s"/g' $cfgdir/config.toml	
    sed -i '' 's/timeout_propose = "3s"/timeout_propose = "3s"/g' $cfgdir/config.toml	
    sed -i '' "s#priv_validator_laddr = \"\"#priv_validator_laddr = \"tcp://0.0.0.0:$privval\"#g" $cfgdir/config.toml	
    sed -i '' 's#allow_duplicate_ip = false#allow_duplicate_ip = true#g' $cfgdir/config.toml	
    sed -i '' 's#log_level = "main:info,state:info,statesync:info,*:error"#log_level = "info"#g' $cfgdir/config.toml	
    sed -i '' 's#addr_book_strict = true#addr_book_strict = false#g' $cfgdir/config.toml	
    sed -i '' "s#external_address = \"\"#external_address = \"tcp://127.0.0.1:$p2p\"#g" $cfgdir/config.toml	
}

function setConfigValidator() {
    cfgdir=$1
    rpc=$2
    p2p=$3
    grpc=$4
    grpcweb=$5
    profile=$6
    sed -i '' "s#127.0.0.1:26657#0.0.0.0:$rpc#g" $cfgdir/config.toml	
    sed -i '' "s#0.0.0.0:26656#0.0.0.0:$p2p#g" $cfgdir/config.toml	
    sed -i '' "s#0.0.0.0:9090#0.0.0.0:$grpc#g" $cfgdir/app.toml
    sed -i '' "s#0.0.0.0:9091#0.0.0.0:$grpcweb#g" $cfgdir/app.toml
    sed -i '' "s#localhost:6060#localhost:$profile#g" $cfgdir/config.toml	
    sed -i '' 's/timeout_commit = "5s"/timeout_commit = "3s"/g' $cfgdir/config.toml	
    sed -i '' 's/timeout_propose = "3s"/timeout_propose = "3s"/g' $cfgdir/config.toml	
    sed -i '' 's#allow_duplicate_ip = false#allow_duplicate_ip = true#g' $cfgdir/config.toml	
    sed -i '' 's#log_level = "main:info,state:info,statesync:info,*:error"#log_level = "info"#g' $cfgdir/config.toml	
    sed -i '' 's#addr_book_strict = true#addr_book_strict = false#g' $cfgdir/config.toml	
    sed -i '' "s#external_address = \"\"#external_address = \"tcp://127.0.0.1:$p2p\"#g" $cfgdir/config.toml	
}

# echo "Creating gaiad instance with home=$CHAINDIR chain-id=$CHAINID..."	
# Build genesis file incl account for passed address	
coins="100000000000stake,100000000000samoleans"	

# Have different home folders for each node	
# Nodes for horcrux
n0dir="$CHAINDIR/$CHAINID/n0"
n1dir="$CHAINDIR/$CHAINID/n1"
n2dir="$CHAINDIR/$CHAINID/n2"
# Other validators
n3dir="$CHAINDIR/$CHAINID/n3"
n4dir="$CHAINDIR/$CHAINID/n4"
n5dir="$CHAINDIR/$CHAINID/n5"

# Nodes for horcrux
home0="--home $n0dir"	
home1="--home $n1dir"	
home2="--home $n2dir"	
# Other validators
home3="--home $n3dir"	
home4="--home $n4dir"	
home5="--home $n5dir"	

# Nodes for horcrux
n0cfgDir="$n0dir/config"	
n1cfgDir="$n1dir/config"	
n2cfgDir="$n2dir/config"	
# Other validators
n3cfgDir="$n3dir/config"	
n4cfgDir="$n4dir/config"	
n5cfgDir="$n5dir/config"	

# Nodes for horcrux
n0cfg="$n0cfgDir/config.toml"	
n1cfg="$n1cfgDir/config.toml"	
n2cfg="$n2cfgDir/config.toml"	
# Other validators
n3cfg="$n3cfgDir/config.toml"	
n4cfg="$n4cfgDir/config.toml"	
n5cfg="$n5cfgDir/config.toml"	
kbt="--keyring-backend="test""	

# Initialize the 2 home directories	
gaiad $home0 --chain-id $CHAINID init n0 &>/dev/null	
gaiad $home1 --chain-id $CHAINID init n1 &>/dev/null	
gaiad $home2 --chain-id $CHAINID init n2 &>/dev/null	
gaiad $home3 --chain-id $CHAINID init n3 &>/dev/null	
gaiad $home4 --chain-id $CHAINID init n4 &>/dev/null	
gaiad $home5 --chain-id $CHAINID init n5 &>/dev/null	

# Add some keys for funds	
# Add horcrux validator key
gaiad $home0 keys add validator $kbt &>/dev/null	
# Add other validator keys
gaiad $home3 keys add validator $kbt &>/dev/null	
gaiad $home4 keys add validator $kbt &>/dev/null	
gaiad $home5 keys add validator $kbt &>/dev/null	
# have a key with some extra funds
gaiad $home0 keys add extra $kbt &>/dev/null	

# Add addresses to genesis	
# Add all validator addresses keys to node0 genesis
gaiad $home0 add-genesis-account $(gaiad $home0 keys $kbt show validator -a) $coins &>/dev/null	
gaiad $home0 add-genesis-account $(gaiad $home3 keys $kbt show validator -a) $coins &>/dev/null	
gaiad $home0 add-genesis-account $(gaiad $home4 keys $kbt show validator -a) $coins &>/dev/null	
gaiad $home0 add-genesis-account $(gaiad $home5 keys $kbt show validator -a) $coins &>/dev/null
# Add extra funds key to node0 genesis
gaiad $home0 add-genesis-account $(gaiad $home0 keys $kbt show extra -a) $coins &>/dev/null	
# Add validator addresses for gentxs to other validators home folders
gaiad $home3 add-genesis-account $(gaiad $home3 keys $kbt show validator -a) $coins &>/dev/null	
gaiad $home4 add-genesis-account $(gaiad $home4 keys $kbt show validator -a) $coins &>/dev/null	
gaiad $home5 add-genesis-account $(gaiad $home5 keys $kbt show validator -a) $coins &>/dev/null	

# Gentxs for each node
gaiad $home0 gentx validator 100000000000stake $kbt --chain-id $CHAINID &>/dev/null	
gaiad $home3 gentx validator 100000000000stake $kbt --chain-id $CHAINID &>/dev/null	
gaiad $home4 gentx validator 100000000000stake $kbt --chain-id $CHAINID &>/dev/null	
gaiad $home5 gentx validator 100000000000stake $kbt --chain-id $CHAINID &>/dev/null	
# Move gentxs to node0 config dir
mv $n3cfgDir/gentx/* $n0cfgDir/gentx &>/dev/null
mv $n4cfgDir/gentx/* $n0cfgDir/gentx &>/dev/null
mv $n5cfgDir/gentx/* $n0cfgDir/gentx &>/dev/null

# finalize genesis
gaiad $home0 collect-gentxs &>/dev/null	

# Copy genesis over to other nodes
cp $n0cfgDir/genesis.json $n1cfgDir/genesis.json	
cp $n0cfgDir/genesis.json $n2cfgDir/genesis.json	
cp $n0cfgDir/genesis.json $n3cfgDir/genesis.json	
cp $n0cfgDir/genesis.json $n4cfgDir/genesis.json	
cp $n0cfgDir/genesis.json $n5cfgDir/genesis.json	

# Set proper defaults and change ports on horcrux nodes
setConfigHorcrux $n0cfgDir 26657 26656 9090 9091 6060 1234
setConfigHorcrux $n1cfgDir 26658 26655 9092 9093 6061 1235
setConfigHorcrux $n2cfgDir 26659 26654 9094 9095 6062 1236
# Set proper defaults and change ports on validator nodes
setConfigValidator $n3cfgDir 26660 26653 9096 9097 6062
setConfigValidator $n4cfgDir 26661 26652 9098 9099 6063
setConfigValidator $n5cfgDir 26662 26651 9100 9101 6064

# Set peers for all nodes	
peer0="$(gaiad $home0 tendermint show-node-id)@127.0.0.1:26656"	
peer1="$(gaiad $home1 tendermint show-node-id)@127.0.0.1:26655"	
peer2="$(gaiad $home2 tendermint show-node-id)@127.0.0.1:26654"	
peer3="$(gaiad $home3 tendermint show-node-id)@127.0.0.1:26653"	
peer4="$(gaiad $home4 tendermint show-node-id)@127.0.0.1:26652"	
peer5="$(gaiad $home5 tendermint show-node-id)@127.0.0.1:26651"	
sed -i '' 's#persistent_peers = ""#persistent_peers = "'$peer1','$peer2','$peer3','$peer4','$peer5'"#g' $n0cfg	
sed -i '' 's#persistent_peers = ""#persistent_peers = "'$peer0','$peer2','$peer3','$peer4','$peer5'"#g' $n1cfg	
sed -i '' 's#persistent_peers = ""#persistent_peers = "'$peer0','$peer1','$peer3','$peer4','$peer5'"#g' $n2cfg	
sed -i '' 's#persistent_peers = ""#persistent_peers = "'$peer0','$peer1','$peer2','$peer4','$peer5'"#g' $n3cfg	
sed -i '' 's#persistent_peers = ""#persistent_peers = "'$peer0','$peer1','$peer2','$peer3','$peer5'"#g' $n4cfg	
sed -i '' 's#persistent_peers = ""#persistent_peers = "'$peer0','$peer1','$peer2','$peer3','$peer4'"#g' $n5cfg	

# Copy priv validator over from node that signed gentx to the signer	
cp $n0cfgDir/priv_validator_key.json $CHAINDIR/priv_validator_key.json	
cd $CHAINDIR
$HORCRUX create-shares ./priv_validator_key.json 2 3
$HORCRUX config init $CHAINID localhost:1234 --home $(pwd)/signer1 --cosigner --peers "tcp://localhost:2223|2,tcp://localhost:2224|3" --threshold 2 --listen "tcp://0.0.0.0:2222"
$HORCRUX config init $CHAINID localhost:1235 --home $(pwd)/signer2 --cosigner --peers "tcp://localhost:2222|1,tcp://localhost:2224|3" --threshold 2 --listen "tcp://0.0.0.0:2223"
$HORCRUX config init $CHAINID localhost:1236 --home $(pwd)/signer3 --cosigner --peers "tcp://localhost:2222|1,tcp://localhost:2223|2" --threshold 2 --listen "tcp://0.0.0.0:2224"
cp ./private_share_1.json ./signer1/share.json	
cp ./private_share_2.json ./signer2/share.json	
cp ./private_share_3.json ./signer3/share.json		
cd ..	

# Start the gaia instances	
./build/horcrux --home ./data/signer1 cosigner start > $CHAINDIR/signer1.log 2>&1 &	
./build/horcrux --home ./data/signer2 cosigner start > $CHAINDIR/signer2.log 2>&1 &	
./build/horcrux --home ./data/signer3 cosigner start > $CHAINDIR/signer3.log 2>&1 &	
sleep 5
gaiad $home0 start --pruning=nothing > $CHAINDIR/$CHAINID.n0.log 2>&1 &	
gaiad $home1 start --pruning=nothing > $CHAINDIR/$CHAINID.n1.log 2>&1 &	
gaiad $home2 start --pruning=nothing > $CHAINDIR/$CHAINID.n2.log 2>&1 &	
gaiad $home3 start --pruning=nothing > $CHAINDIR/$CHAINID.n3.log 2>&1 &	
gaiad $home4 start --pruning=nothing > $CHAINDIR/$CHAINID.n4.log 2>&1 &	
gaiad $home5 start --pruning=nothing > $CHAINDIR/$CHAINID.n5.log 2>&1 &	

echo	
echo "Logs:"	
echo "  - n0 'tail -f ./data/signer1.log'"	
echo "  - n1 'tail -f ./data/signer2.log'"	
echo "  - n2 'tail -f ./data/signer3.log'"	
echo "  - f0 'tail -f ./data/test-chain-id.n0.log'"	
echo "  - f1 'tail -f ./data/test-chain-id.n1.log'"
echo "  - f1 'tail -f ./data/test-chain-id.n2.log'"
echo "  - f1 'tail -f ./data/test-chain-id.n3.log'"
echo "  - f1 'tail -f ./data/test-chain-id.n4.log'"
echo "  - f1 'tail -f ./data/test-chain-id.n5.log'"
