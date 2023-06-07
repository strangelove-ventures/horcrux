package signer

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/strangelove-ventures/horcrux/signer/testdata"
	"github.com/stretchr/testify/require"
)

func TestLoadCosignerEd25519Key(t *testing.T) {
	tmp := t.TempDir()

	rsaKeyFile := filepath.Join(tmp, "rsa_keys.json")

	err := os.WriteFile(rsaKeyFile, testdata.RSAKeys, 0600)
	require.NoError(t, err)

	key, err := LoadCosignerRSAKey(rsaKeyFile)
	require.NoError(t, err)
	require.Equal(t, key.ID, 3)

	// public key from cosigner pubs array should match public key from our private key
	require.Equal(t, &key.RSAKey.PublicKey, key.RSAPubs[key.ID-1])
}
