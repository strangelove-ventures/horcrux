package testdata

import (
	_ "embed" // required to embed files
)

//go:embed rsa_keys.json
var RSAKeys []byte
