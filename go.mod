module github.com/jackzampolin/horcrux

go 1.15

require (
	github.com/BurntSushi/toml v0.3.1
	github.com/Nvveen/Gotty v0.0.0-20120604004816-cd527374f1e5 // indirect
	github.com/avast/retry-go v3.0.0+incompatible
	github.com/cenkalti/backoff/v3 v3.0.0 // indirect
	github.com/cosmos/cosmos-sdk v0.42.3
	github.com/gogo/protobuf v1.3.3
	github.com/mitchellh/go-homedir v1.1.0 // indirect
	github.com/ory/dockertest v3.3.5+incompatible // indirect
	github.com/ory/dockertest/v3 v3.7.0 // indirect
	github.com/spf13/cobra v1.1.3
	github.com/spf13/viper v1.7.1 // indirect
	github.com/stretchr/testify v1.7.0
	github.com/tendermint/go-amino v0.16.0
	github.com/tendermint/tendermint v0.34.8
	github.com/testcontainers/testcontainers-go v0.10.0
	gitlab.com/polychainlabs/edwards25519 v0.0.0-20200206000358-2272e01758fb
	gitlab.com/polychainlabs/threshold-ed25519 v0.0.0-20200221030822-1c35a36a51c1
	golang.org/x/sync v0.0.0-20210220032951-036812b2e83c
	gopkg.in/yaml.v2 v2.4.0 // indirect
)

replace github.com/gogo/protobuf => github.com/regen-network/protobuf v1.3.3-alpha.regen.1
