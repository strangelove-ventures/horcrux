package nodesecurity_test

import (
	"crypto/rand"
	"encoding/json"
	"testing"

	"github.com/ethereum/go-ethereum/crypto/ecies"
	"github.com/ethereum/go-ethereum/crypto/secp256k1"
	"github.com/strangelove-ventures/horcrux/src/cosigner/nodesecurity"

	"github.com/stretchr/testify/require"
	"golang.org/x/sync/errgroup"
)

func TestCosignerECIES(t *testing.T) {
	t.Parallel()

	keys := make([]*ecies.PrivateKey, 3)
	pubs := make([]*ecies.PublicKey, 3)

	for i := 0; i < 3; i++ {
		key, err := ecies.GenerateKey(rand.Reader, secp256k1.S256(), nil)
		require.NoError(t, err)

		keys[i] = key
		pubs[i] = &key.PublicKey
	}

	securities := make([]nodesecurity.CosignerSecurityECIES, 3)

	for i := 0; i < 3; i++ {
		key := nodesecurity.CosignerECIESKey{
			ID:        i + 1,
			ECIESKey:  keys[i],
			ECIESPubs: pubs,
		}
		securities[i] = *nodesecurity.NewCosignerSecurityECIES(key)

		bz, err := json.Marshal(&key)
		require.NoError(t, err)

		var key2 nodesecurity.CosignerECIESKey
		require.NoError(t, json.Unmarshal(bz, &key2))
		require.Equal(t, key, key2)

		require.Equal(t, key.ECIESKey.D.Bytes(), key2.ECIESKey.D.Bytes())

		for i := 0; i < 3; i++ {
			require.Equal(t, key.ECIESPubs[i].X.Bytes(), key2.ECIESPubs[i].X.Bytes())
			require.Equal(t, key.ECIESPubs[i].Y.Bytes(), key2.ECIESPubs[i].Y.Bytes())
		}
	}

	err := testCosignerSecurityECIES(t, securities)
	require.ErrorContains(t, err, "ecies: invalid message")
	require.ErrorContains(t, err, "failed to decrypt")
}

func testCosignerSecurityRSA(t *testing.T, securities []*nodesecurity.CosignerSecurityRSA) error {
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

func testCosignerSecurityECIES(t *testing.T, securities []nodesecurity.CosignerSecurityECIES) error {
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
func TestConcurrentIterateCosignerECIES(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping in short mode")
	}

	keys := make([]*ecies.PrivateKey, 3)
	pubs := make([]*ecies.PublicKey, 3)

	for i := 0; i < 3; i++ {
		key, err := ecies.GenerateKey(rand.Reader, secp256k1.S256(), nil)
		require.NoError(t, err)

		keys[i] = key
		pubs[i] = &key.PublicKey
	}

	securities := make([]*nodesecurity.CosignerSecurityECIES, 3)

	for i := 0; i < 3; i++ {
		securities[i] = nodesecurity.NewCosignerSecurityECIES(
			nodesecurity.CosignerECIESKey{
				ID:        i + 1,
				ECIESKey:  keys[i],
				ECIESPubs: pubs,
			})
	}

	for i := 0; i < 5000; i++ {
		var eg errgroup.Group
		for i, security := range securities {
			security := security
			i := i
			eg.Go(func() error {
				var nestedEg errgroup.Group
				for j, security2 := range securities {
					if i == j {
						continue
					}
					security2 := security2
					j := j
					nestedEg.Go(func() error {
						n, err := security.EncryptAndSign(j+1, []byte("mock_pub"), []byte("mock_share"))
						if err != nil {
							return err
						}

						_, _, err = security2.DecryptAndVerify(i+1, n.PubKey, n.Share, n.Signature)
						if err != nil {
							return err
						}
						return nil
					})
				}
				return nestedEg.Wait()
			})
		}
		require.NoErrorf(t, eg.Wait(), "success count: %d", i)
	}
}
