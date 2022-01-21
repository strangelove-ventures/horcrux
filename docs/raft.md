# Raft consensus algorithm - signer nodes implementation

The raft protocol is used in the horcrux signer cluster for the purposes of leader election and event based communication amongst co-signers for sharing signatures.

All sign requests from the sentries made to any signer node are proxied through the raft leader.
The signer node that is the current elected raft leader will act upon the sign requests by managing the threshold validation process:

- Check the requested block against the high watermark file to avoid double signing.
- Emit an HRS event, with the current height, round, and step, through the raft cluster to initiate the ephemeral secret sharing amongst the signers.
- Signers will act upon the HRS event by generating the ephemeral nonce shares for all other signers (encrypted with the destination signer's RSA public key), and writing them to a specific key in the raft key-value store designated for the destination signer.
- This signer-specific ephemeral share event will be handled by the destination signer. It will decrypt the ephemeral share with the RSA private key, verify the signature to verify the identity of the source signer, save it in memory as HRS metadata, and emit a receipt event to inform the raft leader that the ephemeral sharing has completed between a set of signers.
- For each signer, the leader will wait until it receives enough ephemeral nonce sharing receipt events to indicate that the specific signer is ready to sign the block with it's share.
- The leader will then emit an event to the specific signer peer with the block bytes to be signed. The peer will sign the bytes with it's key share, then emit an event back to the leader with the signature.
- The leader will wait until the threshold number of signers have completed this process (including itself), and then assemble the combined signature. Upon validation, the high watermark file will be updated with the current block, and the signature will be returned to the requesting sentry for submission.

With event-based communication and leader election, the cluster can reliably sign when `(total - threshold)` signers are down. If a signer node goes down and it is not the leader, there should not be any missed blocks. If the leader goes down, a new leader will be elected and it will pick up signing blocks after that, so there might be a few missed blocks in the case of a downed leader.