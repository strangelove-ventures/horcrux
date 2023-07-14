package signer

import (
	"testing"

	ecies "github.com/ecies/go/v2"
	"github.com/stretchr/testify/require"
)

func TestCosignerECIES(t *testing.T) {
	key1, err := ecies.GenerateKey()
	require.NoError(t, err)

	key2, err := ecies.GenerateKey()
	require.NoError(t, err)

	key3, err := ecies.GenerateKey()
	require.NoError(t, err)

	pubKeys := []CosignerECIESPubKey{
		{
			ID:        1,
			PublicKey: key1.PublicKey,
		},
		{
			ID:        2,
			PublicKey: key2.PublicKey,
		},
		{
			ID:        3,
			PublicKey: key3.PublicKey,
		},
	}

	s1 := NewCosignerSecurityECIES(
		CosignerECIESKey{
			ID:       1,
			ECIESKey: key1,
		},
		pubKeys,
	)

	s2 := NewCosignerSecurityECIES(
		CosignerECIESKey{
			ID:       2,
			ECIESKey: key2,
		},
		pubKeys,
	)

	s3 := NewCosignerSecurityECIES(
		CosignerECIESKey{
			ID:       3,
			ECIESKey: key3,
		},
		pubKeys,
	)

	var (
		mockPub   = []byte("mock_pub")
		mockShare = []byte("mock_share")
	)

	nonce, err := s1.EncryptAndSign(2, mockPub, mockShare)
	require.NoError(t, err)

	decryptedPub, decryptedShare, err := s2.DecryptAndVerify(1, nonce.PubKey, nonce.Share, nonce.Signature)
	require.NoError(t, err)

	require.Equal(t, mockPub, decryptedPub)
	require.Equal(t, mockShare, decryptedShare)

	_, _, err = s3.DecryptAndVerify(1, nonce.PubKey, nonce.Share, nonce.Signature)
	require.ErrorContains(t, err, "cannot decrypt ciphertext: cipher: message authentication failed")
}
