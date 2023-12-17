package testdata

import (
	_ "embed" // required to embed files
)

//go:embed config-migrated.yaml
var ConfigMigrated string

//go:embed config-v2.yaml
var ConfigV2 []byte

//go:embed cosigner-key-migrated-ed25519.json
var CosignerKeyMigrated string

//go:embed cosigner-key-migrated-rsa.json
var CosignerRSAKeyMigrated string

//go:embed cosigner-key-v2.json
var CosignerKeyV2 []byte
