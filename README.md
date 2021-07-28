# Horcrux

Horcrux is a [multi-party-computation](https://en.wikipedia.org/wiki/Secure_multi-party_computation) signing service for Tendermint nodes using threshold Ed25519 signatures. 

## Refactor 

Pylon Validation Services is currently maintaining and refactoring this codebase. The following are goals of the refactor:

- [ ] Refactor existing code into a [`cobra`](https://github.com/spf13/cobra) CLI
  * [ ] Enable configuration via `ENV`
  * [ ] Seperate functionality into different commands 
  * [ ] Document code, security assumptions, and system functionality
- [ ] Add robust test suite to ensure operation against specific versions of the [`cosmos-sdk`](https://github.com/cosmos/cosmos-sdk) and [`tendermint`](https://github.com/tendermint/tendermint)
  * [ ] Use `dockertest` framework to spin up 

## Design

Validator operators for tendermint chains balance operational and risk tradeoffs to avoid penalties via slashing for liveliness faults or double signing blocks.

Traditional high-availability systems where the keys exist on hot spares risk double signing if there are failover detection bugs. Low-availability systems, or manual failover, risk downtime if manual intervention cannot respond in a timely manner.

Multi-party computation using threshold signatures is able to provide high-availability while maintaining high security and avoiding double signing via failover detection bugs.

## Running Horcrux

See documentation in [`docs/setup.md`](/docs/setup.md)

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