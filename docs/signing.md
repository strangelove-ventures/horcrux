
# Horcrux MPC Signing

## Private Key Sharding and Number of Nodes

To provide private key security, The key is sharded into multiple pieces using [Ed25519 Threshold Signatures](https://gitlab.com/unit410/threshold-ed25519). Two numbers are used for this operation:
- _Number of shards (n)_: How many total pieces should the key be split into?
- _Threshold (t)_: How many of the pieces should be required to assemble a complete signature?

Each piece of the key is added to a relative signer node that will run the horcrux application. These signer nodes are apart of an overall Horcrux cluster that will communicate with each other to sign each block, as requested by the configured sentry node(s).

A higher threshold _`t`_ equates to more security, since more pieces of the key will be required to assemble a full signature. A higher threshold also means the fault tolerance is lower since you cannot tolerate as many missing participants, or in Horcrux' case, failed nodes. It is important to think about your specific use case to determine what the balance of _`n`_ and _`t`_. 

> IMPORTANT: For security and to ensure that there cannot be a situation in which there are two separate clusters of signer nodes that could combine a full signature, it is required that _`t > n/2`_

The recommended configuration for most validators is _`n: 3`_ and _`t: 2`_. This is also the minimum supported _`n`_. This configuration will allow one failed signer node at any given time and will have high performance since only 2 nodes will be required to assemble a full signature for a block. 

_`n: 5`_ and _`t: 3`_ is also a good configuration to enable higher availability at the expense of slightly longer block sign times since 3 nodes will be required to assemble a full signature. 

Horcrux is designed with performance in mind, so it will sign and return the full block signature as soon as _`t`_ signer nodes have participated in the block signature.

### Horcrux multi-party computation (MPC) signing flow

The [Raft](https://raft.github.io/) protocol, specifically the [hashicorp/raft](https://github.com/hashicorp/raft) golang implementation, is used in the Horcrux cluster for the purposes of leader election and high watermark consensus to provide fault tolerance and double sign avoidance.

Each block sign request (votes and proposals) from any connected sentry node(s), made to any signer node, is proxied through the raft leader. This ensures that there is a single node that manages the overall threshold signing flow for any given block. It also ensures that even though each connected sentry will make requests for every block, the only request that will be acted upon is the one which first reaches the signer node that is currently the elected leader. This enables a High Evailability (HA) validator with multiple sentry nodes and multiple signer nodes, enabling the validator to continue signing blocks even in the case of outages on signer and sentry nodes.

### Fault tolerance
- For the sentry nodes, the cluster needs at least one sentry that is in sync with the chain and connected to a signer node that is up and participating in the raft cluster. E.g. if the signer cluster is operational, for a 3 sentry configuration, 2 sentries can have failures and the validator will continue signing blocks.
- For the horcrux signer nodes, the cluster needs at least the threshold number of signer nodes to be up and connected to each other via the raft protocol and be able to reach those same signer nodes via the p2p (RPC) port. E.g. if horcrux is configured as 3 signer nodes, and the private key is sharded into 3 pieces with threshold 2, then 2 signer nodes must be operational for the validator to continue signing blocks.

### Threshold Validator Signing Process

The signer node that is the current elected raft leader will act upon the sign requests by managing the threshold validation process:

- Check the requested block against the high watermark file (kept in consensus between the signer nodes) to avoid double signing.
- Request ephemeral nonces for the block signature from each signer node peer.
- Each signer will act upon the request by generating the ephemeral nonce shares for all other signers (encrypted with the destination signer's RSA public key). These shares will be the response to the leader.
- The leader will wait until it has received _`t - 1`_ responses. The signer nodes which responded in time, _`blockSigners`_ are the signers that will be included with the leader for signing the block.
- The leader will then make a request to each of the _`blockSigners`_ to set the ephemeral nonces for the other signers that are participating in the block signing (_`blockSigners`_ and leader), and produce the signature part from the block data.
- The participant in _`blockSigners`_ will handle this request by decrypting the ephemeral shares with its RSA private key, verify the signatures of the ephemeral share to verify the identity of the source signers, and then save it in memory. After all of the nonces are saved (consensus with the leader and _`blockSigners`_), it will produce its signature piece for the block data and respond to the leader with it.
- Once the leader receives the signature parts from all of the _`blockSigners`_, it will make a combined signature including its own signature part and those from the _`blockSigners`_
- The leader will verify the combined signature is valid, then update its own high watermark file and also emit the block metadata (height, round, and step), to the rest of the signers through raft in order to update their high watermark files. This gives the cluster consensus on what the last successfully signed block was.
- The leader will finally respond with the combined signature for the block, either directly to the requesting sentry if the raft leader was the one who handled the sentry request, or the signer that proxied the request to the leader, which would then respond to the requesting sentry.
