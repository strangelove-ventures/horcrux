module github.com/strangelove-ventures/horcrux

go 1.15

require (
	github.com/BurntSushi/toml v0.4.1
	github.com/avast/retry-go v3.0.0+incompatible
	github.com/cosmos/cosmos-sdk v0.44.2
	github.com/gogo/protobuf v1.3.3
	github.com/matttproud/golang_protobuf_extensions v1.0.2-0.20181231171920-c182affec369 // indirect
	github.com/mitchellh/go-homedir v1.1.0
	github.com/ory/dockertest v3.3.5+incompatible
	github.com/spf13/cobra v1.2.1
	github.com/spf13/viper v1.8.1
	github.com/stretchr/testify v1.7.0
	github.com/tendermint/go-amino v0.16.0
	github.com/tendermint/tendermint v0.34.13
	gitlab.com/polychainlabs/edwards25519 v0.0.0-20200206000358-2272e01758fb
	gitlab.com/polychainlabs/threshold-ed25519 v0.0.0-20200221030822-1c35a36a51c1
	golang.org/x/sync v0.0.0-20210220032951-036812b2e83c
	gopkg.in/yaml.v2 v2.4.0
)

replace github.com/gogo/protobuf => github.com/regen-network/protobuf v1.3.3-alpha.regen.1

replace github.com/keybase/go-keychain => github.com/99designs/go-keychain v0.0.0-20191008050251-8e49817e8af4
