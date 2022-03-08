package signer

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestLoadCosignerKey(t *testing.T) {
	key, err := LoadCosignerKey("./fixtures/cosigner-key.json")
	require.NoError(t, err)
	require.Equal(t, key.ID, 3)

	// public key from cosigner pubs array should match public key from our private key
	require.Equal(t, &key.RSAKey.PublicKey, key.CosignerKeys[key.ID-1])
}
