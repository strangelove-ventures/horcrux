package signer

import (
	"crypto/rand"
	"crypto/rsa"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestCosignerRSA(t *testing.T) {
	key1, err := rsa.GenerateKey(rand.Reader, bitSize)
	require.NoError(t, err)

	key2, err := rsa.GenerateKey(rand.Reader, bitSize)
	require.NoError(t, err)

	key3, err := rsa.GenerateKey(rand.Reader, bitSize)
	require.NoError(t, err)

	pubKeys := []CosignerRSAPubKey{
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

	s1 := NewCosignerSecurityRSA(
		CosignerRSAKey{
			ID:     1,
			RSAKey: *key1,
		},
		pubKeys,
	)

	s2 := NewCosignerSecurityRSA(
		CosignerRSAKey{
			ID:     2,
			RSAKey: *key2,
		},
		pubKeys,
	)

	s3 := NewCosignerSecurityRSA(
		CosignerRSAKey{
			ID:     3,
			RSAKey: *key3,
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
	require.ErrorIs(t, rsa.ErrDecryption, err)
}
