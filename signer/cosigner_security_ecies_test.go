package signer

import (
	"testing"

	ecies "github.com/ecies/go/v2"
	"github.com/stretchr/testify/require"
)

func TestCosignerECIES(t *testing.T) {
	t.Parallel()

	keys := make([]*ecies.PrivateKey, 3)
	pubKeys := make([]CosignerECIESPubKey, 3)

	for i := 0; i < 3; i++ {
		key, err := ecies.GenerateKey()
		require.NoError(t, err)

		keys[i] = key

		pubKeys[i] = CosignerECIESPubKey{
			ID:        i + 1,
			PublicKey: key.PublicKey,
		}
	}

	securities := make([]CosignerSecurity, 3)

	for i := 0; i < 3; i++ {
		securities[i] = NewCosignerSecurityECIES(CosignerECIESKey{
			ID:       i + 1,
			ECIESKey: keys[i],
		},
			pubKeys)
	}

	err := testCosignerSecurity(t, securities)
	require.ErrorContains(t, err, "cannot decrypt ciphertext: cipher: message authentication failed")
}

func testCosignerSecurity(t *testing.T, securities []CosignerSecurity) error {
	var (
		mockPub   = []byte("mock_pub")
		mockShare = []byte("mock_share")
	)

	nonce, err := securities[0].EncryptAndSign(2, mockPub, mockShare)
	require.NoError(t, err)

	decryptedPub, decryptedShare, err := securities[1].DecryptAndVerify(1, nonce.PubKey, nonce.Share, nonce.Signature)
	require.NoError(t, err)

	require.Equal(t, mockPub, decryptedPub)
	require.Equal(t, mockShare, decryptedShare)

	_, _, err = securities[2].DecryptAndVerify(1, nonce.PubKey, nonce.Share, nonce.Signature)

	return err
}
