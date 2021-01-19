package signer

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestLoadCosignerKey(test *testing.T) {
	key, err := LoadCosignerKey("../../test/cosigner-key.json")
	require.NoError(test, err)
	require.Equal(test, key.ID, 3)

	// public key from cosigner pubs array should match public key from our private key
	require.Equal(test, &key.RSAKey.PublicKey, key.CosignerKeys[key.ID-1])
}
