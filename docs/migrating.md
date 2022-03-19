# Migrating from Single Validator Instance to Signer Cluster

## Disclaimer

Before starting, \***\*please make sure to have a clear understanding of node and validator operational requirements\*\***. This guide is medium to high difficulty. Operation of `horcrux` assumes significant prior knowledge of these systems. Debugging problems that may arise will entail a significant amount financial risk (double sign) if you are running on mainnet so a clear understanding of the systems you are working with is important. Please attempt this operation on a testnet before you do so on a mainnet validator.

> **CAUTION:** This operation will require you to take your validator down for some time. If you work quickly and follow the guide, this downtime shouldn't be more than 5-10 minutes. But reguardless, be aware of the downtime slashing on your chain and be careful not to exceed that limit.

## Validator System Migration

This document will describe a migration from a "starting system" to a 2-of-3 multisig cluster running `horcrux`, signing blocks for an array of 3 sentry nodes connected to the p2p network for your particular network. The starting system is a single node performing all these operations: i.e. a full node that is also a validator node which is signing with a `$NODE_HOME/config/priv_validator_key.json` running on a single VM. If you have a different starting system (say 2 sentry nodes and a validator connected to them) map the existing resources onto the desired final state to make your migration with a similar structure to what is described here.

### Example Starting Infrastructure

- VM: 4 CPU, 16 GB RAM, 500GB SSD storage running fully synced chain daemon also acting as a validator

### Example Migration Infrastrcuture

- Sentries: 3x VM w/ 4 CPU, 16GB RAM, 500GB SSD storage running fully synced chain daemon
  - These chain daemons should only expose the `:26656` (p2p) port to the open internet
  - The daemons will need to expose `:1234` (priv validator port) to the `horcrux` nodes, but not to the open internet
- Signers: 3x VM w/ 1 CPU, 1 GB RAM, 20 GB SSD storage running `horcux`
  - These nodes should not expose any ports to the open internet and should only connect with the sentries

## Migration Steps

### 1. Setup Full Nodes

The first step to the migration is to sync the full nodes you will be using as sentries. To follow this guide, ensure that you have 3 nodes from the chain you are validating on which are synced. Follow the instructions for the individual chain for spinning up those nodes. This is the part of setting up `horcrux` that takes the longest.

> **NOTE:** This is also a great usecase for [state sync](https://blog.cosmos.network/cosmos-sdk-state-sync-guide-99e4cf43be2f). Or one of the [quick sync services](https://quicksync.io/) that exist.

### 2. Setup Signer Nodes

To setup the signer nodes, start by recording the private IPs for each of the signer and sentry nodes. Order matters, and you will need these values to configure the signers. Make a table like so:

```bash
# EXAMPLE
sentry-1: 10.168.0.1
sentry-2: 10.168.0.2
sentry-3: 10.168.0.3

signer-1: 10.168.1.1
signer-2: 10.168.1.2
signer-3: 10.168.1.3
```

When installing `horcrux` we recommend using the prebuilt binaries from the [releases page](https://github.com/strangelove-ventures/horcrux/releases). Pick the release cooresponding to the `tendermint` dependancy for the `go.mod` of your chain binary. You should be able to get this with `{binary} version --long`. Install like so:

```bash
# On each signer VM
$ wget https://github.com/strangelove-ventures/horcrux/releases/download/v2.0.0-beta3/horcrux_2.0.0-beta3_linux_amd64.tar.gz
$ tar -xzf horcrux_2.0.0-beta3_linux_amd64.tar.gz
$ sudo mv horcrux /usr/bin/horcrux && rm horcrux_2.0.0-beta3_linux_amd64.tar.gz README.md LICENSE.md
```

Once the binary is installed in `/usr/bin`, install the `systemd` unit file. You can find an [example here](./horcrux.service):

```bash
# On each signer VM
$ sudo nano /etc/systemd/system/horcrux.service
# copy file contents and modify to fit your environment
$ sudo systemctl daemon-reload
```

After that is done, initialize the configuration for each node using the `horcrux` cli. Each node will require a slightly different command. Below are the commands for each of the 3 signer nodes given the private IPs above. Input your own data here:

```bash
# Run this command on the signer-1 VM
# signer-1 connects to sentry-1
$ horcrux config init {my_chain_id} "tcp://10.168.0.1:1234" -c -p "tcp://10.168.1.2:2222|2,tcp://10.168.1.3:2222|3" -l "tcp://10.168.1.1:2222" -t 2 --timeout 1500ms

# Run this command on the signer-2 VM
# signer-2 connects to sentry-2
$ horcrux config init {my_chain_id} "tcp://10.168.0.2:1234" -c -p "tcp://10.168.1.1:2222|1,tcp://10.168.1.3:2222|3" -l "tcp://10.168.1.2:2222" -t 2 --timeout 1500ms

# Run this command on the signer-3 VM
# signer-3 connects to sentry-3
$ horcrux config init {my_chain_id} "tcp://10.168.0.3:1234" -c -p "tcp://10.168.1.1:2222|1,tcp://10.168.1.2:2222|2" -l "tcp://10.168.1.3:2222" -t 2 --timeout 1500ms
```

> **NOTE:** Note the node address (e.g. "tcp://10.168.0.1:1234") of each command. In this example, each horcrux node is communicating with a corresponding sentry. It is also possible to include a comma separated list of node addresses (e.g. "tcp://chain-node-1:1234,tcp://chain-node-2:1234", etc), allowing all horcrux nodes to communicate with all sentries.

> **NOTE:** The `-c` or `--cosigner` flag here says to configure the signer for cosigner operations. The signer can also be run in single signer configuration, if you want to do that don't pass `-c`, `-p` or `-t` or `--timeout`.

> **NOTE:** The `-p` or `--peers` flag lets you set the addresses of the other signer nodes in the config. Two ports are required, the P2P port for RCP traffic, and the Raft port for key-value sharing. Note that each signer also has an index. This index corresponds to the shard of the private key it will sign with. Keeping the node names and the indexes the same helps avoid errors and allows you to work more quickly

> **NOTE:** The `-l` or `--listen` flag lets you set the listen address for the cosigner, which is used for communication between cosigners, Raft and GRPC. The DNS/IP used for this must be reachable by the other peers, i.e. do not use 0.0.0.0 for the hostname.

> **NOTE:** The `-k` or `--keyfile` flag lets you set the file path for the private key share file if you would like to use a different path than `~/.horcrux/share.json`.

> **NOTE:** The `--timeout` value defaults to `1000ms`. If you are running in disconnected data centers (i.e. accross amazon AZs or gcp zones) increasing the timeout slightly helps to avoid missed blocks especially around proposals.

### 3. Split `priv_validator_key.json` and distribute key material

> **CAUTION:** **The security of any key material is outside the scope of this guide. The suggested proceedure here is not necessarily the one you will use. We aim to make this guide easy to understand, not necessarily the most secure. The tooling here is all written in go and can be compiled and used in an airgapped setup if needed. Please open issues if you have questions around how to fit `horcrux` into your infra.**

On some computer that contains your `priv_validator_key.json` create a folder to split the key through the following command. This may take a moment o complete:

```bash
$ ls
priv_validator_key.json

$ horcrux create-shares priv_validator_key.json 2 3
Created Share 1
Created Share 2
Created Share 3

$ ls
priv_validator_key.json
private_share_1.json
private_share_2.json
private_share_3.json
```

The shares need to be moved their co-responding signer nodes at `~/.horcrux/share.json`. It is very important to make sure the share id (in `private_share_<id>.json`) is on the corresponding cosigner node otherwise your signer cluster won't communicate properly and will not sign blocks. If you have named your nodes with their index as the signer index, as in this guide, this operation should be easy to check.

At the end of this step, each of your horcrux nodes will have a `~/.horcrux/share.json` file with the contents matching the appropriate `private_share_<id>.json` file corresponding to the node number.

### 4. Halt your validator node and supply signer state data `horcrux` nodes

Now is the moment of truth. There will be a few minutes of downtime for this step, so ensure you have read the following directions completely before moving forward.

You need to take your validator offline and trust that the `horcrux` setup you have created is going to pick up signing for you soon. Ensure the validator is off and not signing.

> **NOTE:** Leave your current validator turned off, but able to be restarted to resume signing in case of failure. When you are certain that the `horcrux` cluster is signing for you and your validator is back online it will be safe to decommission the old infrastructure.

Once the validator has been stopped, you will need the contents of the `$NODE_HOME/data/priv_validator_state.json` file. This file represents the last time your validator key was used to sign for consensus and acts as a "high water" mark to prevent your validator from doublesigning. `horcrux` uses the same file structure to provide this service. Each node maintains the last state that the node signed as well as the last state the whole cluster signed. In this way we can assure that the cluster doesn't doublesign. It should look something like the below:

```json
{
  "height": "361402",
  "round": 0,
  "step": 3,
  "signature": "IEOS7EJ8C6ZZxwwXiGeMhoO8mwtgTiq6VPR/F1cpLZuz0ZvUZdsgQjTt0GniAIgosfEjC5izKw4Nvvs3ZIceAw==",
  "signbytes": "6B080211BA8305000000000022480A205D4E1F722F53A3FD9E0D28639D7CE7B588338570EBA5C340687C30609C47BCA41224080112208283B6E16BEA46797F8AD4EE0ACE424AC7A4827202446B2D56E7F4438541B7BD2A0C08E4ACE28B0610CCD0AC830232066A756E6F2D31"
}
```

You will need to replace the contents of the `~/.horcrux/state/{chain-id}_priv_validator_state.json` and `~/.horcrux/state/{chain-id}_share_sign_state.json` on each signer node with a truncated and slightly modified version of the file. Note the `""` especially on the `"round"` value:

```json
{
  "height": "361402",
  "round": "0",
  "step": 3
}
```

> **NOTE:** This step can be error prone. We will be [adding a feature](https://github.com/strangelove-ventures/horcrux/issues/18) to allow using the CLI to set these values but for now `nano`/`vi`, `cat` and [`jq`](https://stedolan.github.io/jq/) are your friends.

### 5. Start the signer cluster

Once you have all of the signer nodes fully configured its time to start them. Start all of them at roughly the same time:

```bash
sudo systemctl start horcrux && journalctl -u horcrux -f
```

The following logs should be flowing on each signer node:

```log
I[2021-09-24|02:10:09.022] Tendermint Validator                         module=validator mode=mpc priv_key=...
I[2021-09-24|02:10:09.023] Starting CosignerRPCServer service           module=validator impl=CosignerRPCServer
I[2021-09-24|02:10:09.025] Signer                                       module=validator pubkey=PubKeyEd25519{9A66109B69C...
I[2021-09-24|02:10:09.025] Starting RemoteSigner service                module=validator impl=RemoteSigner
E[2021-09-24|02:10:09.027] Dialing                                      module=validator err="dial tcp 10.180.0.16:1234...
I[2021-09-24|02:10:09.027] Retrying                                     module=validator sleep(s)=3 address=tcp://10.180...
...
```

The signer will continue retrying attempts to reach the sentries until we turn the sentry `priv_validator` listener on in the next step. Any panic causing errors are likely due to one of the two following issues:

- Misnaming or incorrect structure of the files in `~/.horcrux/state`. Double check these if you see errors
- Misnaming or misplacement of the `~/.horcrux/share.json` file

> **NOTE:** leaving these logs streaming in seperate terminal windows will enable you to watch the cluster connect to the sentries.

### 6. Configure and start your full nodes

Once the signer cluster has started successfully its time to reconfigure and restart your sentry nodes. On each node enable the priv validator listener and verify config changes with the following commands:

```bash
$ sed -i 's#priv_validator_laddr = ""#priv_validator_laddr = "tcp://0.0.0.0:1234"#g' $NODE_HOME/config/config.toml
$ cat $NODE_HOME/config/config.toml | grep priv_validator_laddr
priv_validator_laddr = "tcp://0.0.0.0:1234"
```

Ensure any local or network firewalls on the sentry machines are allowing communication from the horcrux cluster to port 1234. Next, restart your nodes for the changes to take effect and see them connect to the signer cluster:

```
$ sudo systemctl restart {node_service} && journalctl -u {node_service} -f
```

Common failure modes:

- Ports on your cloud service aren't properly configured and prevent signers/sentries from communicating
- Node crashes because the signer didn't retry in time, can be fixed by trying again and/or restarting signer. May take some fiddling

### 7. CONGRATS!

You now can sleep much better at night because you are much less likely to have a down validator wake you up in the middle of the night. You have also completed a stressful migration on a production system. Go run around outside screaming, pet your dog, eat a nice meal, hug your kids/significant other, etc... and enjoy the rest of your day!

### 8. Administration Commands

`horcrux elect` - Elect a new cluster leader. Pass an optional argument with the intended leader ID to elect that cosigner as the new leader, e.g. `horcrux elect 3` to elect cosigner with `ID: 3` as leader

`horcrux cosigner address` - Get the public key address as both hex and optionally the validator consensus bech32 address. To retrieve the valcons bech32 address, pass an optional argument with the chain's bech32 valcons prefix, e.g. `horcrux cosigner address cosmosvalcons`
