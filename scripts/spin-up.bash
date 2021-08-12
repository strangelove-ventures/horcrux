#!/bin/sh
# USAGE: ./one-chain test-chain-id ./data	

CHAINID=test-chain-id	
CHAINDIR=./data	

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
sed -i '' 's#allow_duplicate_ip = false#allow_duplicate_ip = true#g' $n0cfg	
sed -i '' 's#log_level = "main:info,state:info,statesync:info,*:error"#log_level = "info"#g' $n0cfg	
sed -i '' 's#addr_book_strict = true#addr_book_strict = false#g' $n0cfg	
sed -i '' 's#external_address = ""#external_address = "tcp://127.0.0.1:26677"#g' $n0cfg	


# Set proper defaults and change ports on n1	
sed -i '' 's#"tcp://127.0.0.1:26657"#"tcp://0.0.0.0:26667"#g' $n1cfg	
sed -i '' 's#"tcp://0.0.0.0:26656"#"tcp://0.0.0.0:26666"#g' $n1cfg	
sed -i '' 's#"0.0.0.0:9090"#"0.0.0.0:9091"#g' $n1cfgDir/app.toml	
sed -i '' 's#"localhost:6060"#"localhost:6061"#g' $n1cfg	
sed -i '' 's/timeout_commit = "5s"/timeout_commit = "1s"/g' $n1cfg	
sed -i '' 's/timeout_propose = "3s"/timeout_propose = "1s"/g' $n1cfg	
sed -i '' 's#priv_validator_laddr = ""#priv_validator_laddr = "tcp://0.0.0.0:1235"#g' $n1cfg	
sed -i '' 's#allow_duplicate_ip = false#allow_duplicate_ip = true#g' $n1cfg	
sed -i '' 's#log_level = "main:info,state:info,statesync:info,*:error"#log_level = "info"#g' $n1cfg	
sed -i '' 's#addr_book_strict = true#addr_book_strict = false#g' $n1cfg	
sed -i '' 's#external_address = ""#external_address = "tcp://127.0.0.1:26677"#g' $n1cfg	


# Set peers for both nodes	
peer0="$(gaiad $home0 tendermint show-node-id)@127.0.0.1:26656"	
peer1="$(gaiad $home1 tendermint show-node-id)@127.0.0.1:26666"	
sed -i '' 's#persistent_peers = ""#persistent_peers = "'$peer1'"#g' $n0cfg	
sed -i '' 's#persistent_peers = ""#persistent_peers = "'$peer0'"#g' $n1cfg	

# Copy priv validator over from node that signed gentx to the signer	
cp $n0cfgDir/priv_validator_key.json $CHAINDIR/priv_validator_key.json	
cd $CHAINDIR	
../build/horcrux create-shares ./priv_validator_key.json 2 3
../build/horcrux config init $CHAINID localhost:1235 --config $(pwd)/signer1/config.yaml --cosigner --peers "tcp://localhost:2223|2,tcp://localhost:2224|3" --threshold 2 --listen "tcp://0.0.0.0:2222"
../build/horcrux config init $CHAINID localhost:1234,localhost:1235 --config $(pwd)/signer2/config.yaml --cosigner --peers "tcp://localhost:2222|1,tcp://localhost:2224|3" --threshold 2 --listen "tcp://0.0.0.0:2223"
../build/horcrux config init $CHAINID localhost:1234 --config $(pwd)/signer3/config.yaml --cosigner --peers "tcp://localhost:2222|1,tcp://localhost:2223|2" --threshold 2 --listen "tcp://0.0.0.0:2224"
cp ./private_share_1.json ./signer1/share.json	
cp ./private_share_2.json ./signer2/share.json	
cp ./private_share_3.json ./signer3/share.json		
cd ..	

# Start the gaia instances	
./build/horcrux cosigner start --config $CHAINDIR/signer1/config.yaml > $CHAINDIR/signer1.log 2>&1 &	
./build/horcrux cosigner start --config $CHAINDIR/signer2/config.yaml > $CHAINDIR/signer2.log 2>&1 &	
./build/horcrux cosigner start --config $CHAINDIR/signer3/config.yaml > $CHAINDIR/signer3.log 2>&1 &	
sleep 5
gaiad $home0 start --pruning=nothing > $CHAINDIR/$CHAINID.n0.log 2>&1 &	
gaiad $home1 start --pruning=nothing > $CHAINDIR/$CHAINID.n1.log 2>&1 &	

echo	
echo "Logs:"	
echo "  - n0 'tail -f ./data/signer1.log'"	
echo "  - n1 'tail -f ./data/signer2.log'"	
echo "  - n2 'tail -f ./data/signer3.log'"	
echo "  - f0 'tail -f ./data/test-chain-id.n0.log'"	
echo "  - f1 'tail -f ./data/test-chain-id.n1.log'"