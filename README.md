# Horcrux

Horcrux is a [multi-party-computation (MPC)](https://en.wikipedia.org/wiki/Secure_multi-party_computation) signing service for Tendermint nodes

## Why use Horcrux?

Take your validator infrastructure to the next level of security and availability

- Composed of a cluster of signer nodes in place of the [remote signer](https://docs.tendermint.com/master/nodes/remote-signer.html), enabling High Availability (HA) for block signing through fault tolerance.
- Secure your validator private key by splitting it across multiple private signer nodes using threshold Ed25519 signatures
- Add security and availability without sacrificing block sign performance.

## Design

Validator operators for tendermint chains balance operational and risk tradeoffs to avoid penalties via slashing for liveliness faults or double signing blocks.

Traditional high-availability systems where the keys exist on hot spares risk double signing if there are failover detection bugs. Low-availability systems, or manual failover, risk downtime if manual intervention cannot respond in a timely manner.

Multi-party computation using threshold signatures is able to provide high-availability while maintaining high security and avoiding double signing via consensus and failover detection mechanisms.

For more on how the Horcrux MPC signing flow works, see [`docs/signing.md`](/docs/signing.md)

## Raft

Horcrux v2.x introduces [Raft](https://raft.github.io/) For leader election and high watermark consensus.

### Benchmarks

![Screenshot from 2022-01-31 13-50-36](https://user-images.githubusercontent.com/6722152/151871074-32cb5d7a-b9f5-4466-8333-abc00bf7aa68.png)

### Demo

Horcrux signer cluster configured with 5 total nodes, threshold 3.

[![Demo](https://img.youtube.com/vi/O-yy1CYBDsI/0.jpg)](https://www.youtube.com/watch?v=O-yy1CYBDsI)

## Running Horcrux

See documentation in [`docs/migrating.md`](/docs/migrating.md) to learn how to upgrade your validator infrastructure with Horcrux.

## Security

Security and management of any key material is outside the scope of this service. Always consider your own security and risk profile when dealing with sensitive keys, services, or infrastructure.

## No Liability

As far as the law allows, this software comes as is,
without any warranty or condition, and no contributor
will be liable to anyone for any damages related to this
software or this license, under any kind of legal claim.

## References

- [Tendermint Validator Documentation](https://docs.tendermint.com/master/tendermint-core/validators.html)
- [Cosmos Hub Validator Documentation](https://hub.cosmos.network/master/validators/overview.html)
- [Provably Secure Distributed Schnorr Signatures and a (t, n) Threshold Scheme for Implicit Certificates](http://cacr.uwaterloo.ca/techreports/2001/corr2001-13.ps)

## Acknowledgement

The initial threshold signing code in this project was developed by Roman Shtylman (@defunctzombie). The work here improves the cluster reliability and performance, adds a nice CLI experience and additional documentation to make operating this software easier and more reliable.