package signer

import (
	"crypto/rand"
	"crypto/rsa"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestCosignerRSA(t *testing.T) {
	t.Parallel()

	keys := make([]*rsa.PrivateKey, 3)
	pubKeys := make([]CosignerRSAPubKey, 3)

	for i := 0; i < 3; i++ {
		key, err := rsa.GenerateKey(rand.Reader, bitSize)
		require.NoError(t, err)

		keys[i] = key

		pubKeys[i] = CosignerRSAPubKey{
			ID:        i + 1,
			PublicKey: key.PublicKey,
		}
	}

	securities := make([]CosignerSecurity, 3)

	for i := 0; i < 3; i++ {
		securities[i] = NewCosignerSecurityRSA(CosignerRSAKey{
			ID:     i + 1,
			RSAKey: *keys[i],
		},
			pubKeys)
	}

	err := testCosignerSecurity(t, securities)
	require.ErrorIs(t, rsa.ErrDecryption, err)
}
