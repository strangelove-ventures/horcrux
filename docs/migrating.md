# Migrating from Single Validator Instance to Signer Cluster

## Disclaimer

Before starting, \***\*please make sure to have a clear understanding of node and validator operational requirements\*\***. This guide is medium to high difficulty. Operation of `horcrux` assumes significant prior knowledge of these systems. Debugging problems that may arise will entail a significant amount financial risk (double sign) if you are running on mainnet so a clear understanding of the systems you are working with is important. Please attempt this operation on a testnet before you do so on a mainnet validator.

> **CAUTION:** This operation will require you to take your validator down for some time. If you work quickly and follow the guide, this downtime shouldn't be more than 5-10 minutes. But regardless, be aware of the downtime slashing on your chain and be careful not to exceed that limit.

## Validator System Migration

This document will describe a migration from a "starting system" to a 2-of-3 multisig cluster running `horcrux`, signing blocks for an array of 3 sentry nodes connected to the p2p network for your particular network. The starting system is a single node performing all these operations: i.e. a full node that is also a validator node which is signing with a `$NODE_HOME/config/priv_validator_key.json` running on a single VM. If you have a different starting system (say 2 sentry nodes and a validator connected to them) map the existing resources onto the desired final state to make your migration with a similar structure to what is described here.

### Example Starting Infrastructure

- VM: 4 CPU, 16 GB RAM, 500GB SSD storage running fully synced chain daemon also acting as a validator

### Example Migration Infrastructure

- Sentries: 3x VM w/ 4 CPU, 16GB RAM, 500GB SSD storage running fully synced chain daemon
  - These chain daemons should only expose the `:26656` (p2p) port to the open internet
  - The daemons will need to expose `:1234` (priv validator port) to the `horcrux` nodes, but not to the open internet
- Signers: 3x VM w/ 1 CPU, 1 GB RAM, 20 GB SSD storage running `horcrux`
  - These nodes should not expose any ports to the open internet and should only connect with the sentries

## Migration Steps

### 1. Setup Chain Nodes

The first step to the migration is to sync the chain nodes (also known as full nodes) that you will be using as sentries. To follow this guide, ensure that you have nodes from the chain you are validating on that are in sync with the latest height of the chain. You can validate with a minimum of one sentry node, but more are recommended for redundancy/availability. We will use three chain nodes for this example. Follow the instructions for the individual chain for spinning up those nodes. This is the part of setting up `horcrux` that takes the longest.

> **NOTE:** This is also a great usecase for [state sync](https://blog.cosmos.network/cosmos-sdk-state-sync-guide-99e4cf43be2f). Or one of the [quick sync services](https://quicksync.io/) that exist.

### 2. Setup Signer Nodes

To setup the signer nodes, start by recording the private IPs or DNS hostnames for each of the signer and sentry (chain) nodes. Order matters, and you will need these values to configure the signers. Make a table like so:

```bash
# EXAMPLE
sentry-1: 10.168.0.1
sentry-2: 10.168.0.2
sentry-3: 10.168.0.3

node-1: 10.168.1.1
node-2: 10.168.1.2
node-3: 10.168.1.3
```

When installing `horcrux` we recommend using either the [container image](https://github.com/strangelove-ventures/horcrux/pkgs/container/horcrux) or the [prebuilt binary](https://github.com/strangelove-ventures/horcrux/releases) for the latest stable release.

The image or binary will be used on each cosigner (bare virtual machine, docker container, kubernetes pod, etc.)
The binary should also be installed on your local machine for working with the config and key files before distributing to the cosigner nodes.

Run the following on your local machine. If you are using the binary on the cosigners rather than container image, run this on each cosigner node VM also.
```bash
TAG=v3.0.0
$ wget https://github.com/strangelove-ventures/horcrux/releases/download/${TAG}/horcrux_${TAG}_linux_amd64.tar.gz
$ tar -xzf horcrux_${TAG}_linux_amd64.tar.gz
$ sudo mv horcrux /usr/bin/horcrux && rm horcrux_${TAG}_linux_amd64.tar.gz README.md LICENSE.md
```

For each cosigner node (not required on local machine): once the binary is installed in `/usr/bin`, install the `systemd` unit file. You can find an [example here](./horcrux.service):

```bash
# On each horcrux cosigner
$ sudo nano /etc/systemd/system/horcrux.service
# copy file contents and modify to fit your environment
$ sudo systemctl daemon-reload
```

After that is done, initialize the shared configuration for the cosigners on your local machine using the `horcrux` cli. If you would like different cosigners to connect to different sentry node(s): repeat this command and modify the `--node` flag values for each cosigner, or modify the config after the initial generation.

```bash
$ horcrux config init --node "tcp://10.168.0.1:1234" --node "tcp://10.168.0.2:1234" --node "tcp://10.168.0.3:1234" --cosigner "tcp://10.168.1.1:2222" --cosigner "tcp://10.168.1.2:2222" --cosigner "tcp://10.168.1.3:2222" --threshold 2 --grpc-timeout 1000ms --raft-timeout 1000ms
```

> **Note** 
> Note the use of multiple `--node` and `--cosigner` flags. In this example, there are 3 sentry (chain) nodes that each horcrux cosigner will connect to. There are 3 horcrux cosigners, with a threshold of 2 cosigners required to sign a valid block signature.

#### Flags

- `-c`/`--cosigner`: configures the P2P address and shard ID for cosigner nodes. Keeping the node names and the IDs the same helps avoid errors. The DNS/IP used for all of these must be reachable by the other cosigners, i.e. do not use 0.0.0.0 for the hostname.
- `-n`/`--node`: configures the priv-val interface listen address for the chain sentry nodes.
- `-k`/`--key-dir`: configures the directory for the RSA and Ed25519 private key files if you would like to use a different path than the default, `~/.horcrux`.
- `--grpc-timeout`: configures the timeout for cosigner-to-cosigner GRPC communication. This value defaults to `1000ms`.
- `--raft-timeout`: configures the timeout for cosigner-to-cosigner Raft consensus. This value defaults to `1000ms`.
- `-m`/`--mode`: this flag allows changing the sign mode. By default, horcrux uses `threshold` mode for MPC cosigner operations. This is the officially-supported configuration. The signer can also be run in single signer configuration for experimental, non-mainnet deployments. To enable single-signer mode, use `single` for this flag, exclude the `-c`, `-t`, `--grpc-timeout`, and `--raft-timeout` flags, and pass the `--accept-risk` flag to accept the elevated risk of running in single signer mode.

> **Warning**
> SINGLE-SIGNER MODE SHOULD NOT BE USED FOR MAINNET! Horcrux single-signer mode does not give the level of improved key security and fault tolerance that Horcrux MPC/cosigner mode provides. While it is a simpler deployment configuration, single-signer should only be used for experimentation as it is not officially supported by Strangelove.


### 3. Generate cosigner communication encryption keys

Horcrux uses secp256k1 keys to encrypt (ECIES) and sign (ECDSA) cosigner-to-cosigner p2p communication. This is done by encrypting the payloads that are sent over GRPC between cosigners. Open your shell to a working directory and generate the ECIES keys that will be used on each cosigner using the `horcrux` CLI on your local machine.

```bash
$ horcrux create-ecies-shards --shards 3
Created ECIES Shard cosigner_1/ecies_keys.json
Created ECIES Shard cosigner_2/ecies_keys.json
Created ECIES Shard cosigner_3/ecies_keys.json

$ ls -R
.:
cosigner_1  cosigner_2  cosigner_3

./cosigner_1:
ecies_keys.json

./cosigner_2:
ecies_keys.json

./cosigner_3:
ecies_keys.json
```

### 4. Shard `priv_validator_key.json` for each chain.

> **CAUTION:** **The security of any key material is outside the scope of this guide. The suggested procedure here is not necessarily the one you will use. We aim to make this guide easy to understand, not necessarily the most secure. This guide assumes that your local machine is a trusted computer. The tooling here is all written in go and can be compiled and used in an airgapped setup if needed. Please open issues if you have questions about how to fit `horcrux` into your infra.**

Horcrux uses threshold Ed25519 cryptography to sign a block payload on the cosigners and combine the resulting signatures to produce a signature that can be validated against your validator's Ed25519 public key. On your local machine which contains your full `priv_validator_key.json` key file(s), shard the key using the `horcrux` CLI in the same working directory as the previous command.

```bash
$ horcrux create-ed25519-shards --chain-id cosmoshub-4 --key-file /path/to/cosmoshub/priv_validator_key.json --threshold 2 --shards 3
Created Ed25519 Shard cosigner_1/cosmoshub-4_shard.json
Created Ed25519 Shard cosigner_2/cosmoshub-4_shard.json
Created Ed25519 Shard cosigner_3/cosmoshub-4_shard.json

$ ls -R
.:
cosigner_1  cosigner_2  cosigner_3

./cosigner_1:
cosmoshub-4_shard.json  ecies_keys.json

./cosigner_2:
cosmoshub-4_shard.json  ecies_keys.json

./cosigner_3:
cosmoshub-4_shard.json  ecies_keys.json
```

If you will be signing for multiple chains with this single horcrux cluster, repeat this step with the `priv_validator_key.json` for each additional chain ID.

### 5. Distribute config file and key shards to each cosigner.

The files need to be moved their corresponding signer nodes in the `~/.horcrux/` directory. It is important to make sure the files for the cosigner `{id}` (in `cosigner_{id}`) are placed on the corresponding cosigner node. If not, the cluster will not produce valid signatures. If you have named your nodes with their index as the signer index, as in this guide, this operation should be easy to check.

At the end of this step, each of your horcrux nodes should have a `~/.horcrux/{chain-id}_shard.json` file for each `chain-id` with the contents matching the appropriate `cosigner_{id}/{chain-id}_shard.json` file corresponding to the node number. Additionally, each of your horcrux nodes should have a `~/.horcrux/ecies_keys.json` file with the contents matching the appropriate `cosigner_{id}/ecies_keys.json` file corresponding to the node number.

### 6. Halt your validator node and supply signer state data `horcrux` nodes

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

You will need to replace the contents of the `~/.horcrux/state/{chain-id}_priv_validator_state.json` on each signer node with a truncated and slightly modified version of the file. Note the `""` especially on the `"round"` value:

```json
{
  "height": "361402",
  "round": "0",
  "step": 3
}
```

`horcrux state import` can be used to import an existing `priv_validator_state.json`

### 7. Start the cosigner cluster

Once you have all of the cosigner nodes fully configured its time to start them. Start all of them at roughly the same time:

```bash
sudo systemctl start horcrux && journalctl -u horcrux -f
```

The following logs should be flowing on each signer node:

```log
I[2023-05-15|20:09:22.988] Horcrux Validator                            module=validator mode=threshold priv-state-dir=/root/.horcrux/state
I[2023-05-15|20:09:22.990] service start                                module=validator msg="Starting CosignerRaftStore service" impl=CosignerRaftStore
I[2023-05-15|20:09:22.991] Local Raft Listening                         module=validator port=2222
I[2023-05-15|20:09:22.993] service start                                module=validator msg="Starting RemoteSigner service" impl=RemoteSigner
I[2023-05-15|20:09:22.993] service start                                module=validator msg="Starting RemoteSigner service" impl=RemoteSigner
I[2023-05-15|20:09:22.993] service start                                module=validator msg="Starting RemoteSigner service" impl=RemoteSigner
E[2023-05-15|20:09:22.994] Dialing                                      module=validator err="dial tcp 10.180.0.16:1234...
I[2023-05-15|20:09:22.995] Retrying                                     module=validator sleep(s)=3 address=tcp://10.180...
...
```

The signer will continue retrying attempts to reach the sentries until we turn the sentry `priv_validator` listener on in the next step. Any panic causing errors are likely due to one of the two following issues:

- Misnaming or incorrect structure of the files in `~/.horcrux/state`. Double check these if you see errors
- Misnaming or misplacement of the `~/.horcrux/{chain-id}_shard.json` file

> **NOTE:** leaving these logs streaming in seperate terminal windows will enable you to watch the cluster connect to the sentries.

### 8. Configure and start your full nodes

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

- Ports on the firewall (cosigner VM, cloud service, LAN port-forwards, etc.) aren't properly opened and prevent signers/sentries from communicating
- Node crashes because the signer didn't retry in time, can be fixed by trying again and/or restarting signer. May take some fiddling

### 9. CONGRATS!

You now can sleep much better at night because you are much less likely to have a down validator wake you up in the middle of the night. You have also completed a stressful migration on a production system. Go run around outside screaming, pet your dog, eat a nice meal, hug your kids/significant other, etc... and enjoy the rest of your day!

### 10. Administration Commands

`horcrux elect` - Elect a new cluster leader. Pass an optional argument with the intended leader ID to elect that cosigner as the new leader, e.g. `horcrux elect 3` to elect cosigner with `shardID: 3` as leader. This is an optimistic leader election, it is not guaranteed that the exact requested leader will be elected.

`horcrux address` - Get the public key address as both hex and optionally the validator consensus bech32 address. To retrieve the valcons bech32 address, pass an optional argument with the chain's bech32 prefix, e.g. `horcrux address cosmos`

## Steps to Migrate a Peer on a New IP

To change the DNS/IP of a cosigner:

- update config files on each cosigner
- bring all cosigners down
- remove the .horcrux/raft directory on all cosigners
- restart all cosigners
