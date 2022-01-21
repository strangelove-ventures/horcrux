# Horcrux

Horcrux is a [multi-party-computation](https://en.wikipedia.org/wiki/Secure_multi-party_computation) signing service for Tendermint nodes using threshold Ed25519 signatures. 

## Design

Validator operators for tendermint chains balance operational and risk tradeoffs to avoid penalties via slashing for liveliness faults or double signing blocks.

Traditional high-availability systems where the keys exist on hot spares risk double signing if there are failover detection bugs. Low-availability systems, or manual failover, risk downtime if manual intervention cannot respond in a timely manner.

Multi-party computation using threshold signatures is able to provide high-availability while maintaining high security and avoiding double signing via failover detection bugs.

Communication between signer nodes utilizes the Raft protocol [`docs/raft.md`](/docs/raft.md) for leader election and event-based communication.

## Running Horcrux

See documentation in [`docs/migrating.md`](/docs/migrating.md)

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

This codebase (and most especially the underlying cryptographic libraries) was developed by Roman Shtylman (@defunctzombie). The work here primarily adds a nice CLI experience and additional documentation to make operating this software easier and, hopefully, more reliable.