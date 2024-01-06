package nodesecurity_test

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"testing"

	"github.com/strangelove-ventures/horcrux/src/cosigner"
	"github.com/strangelove-ventures/horcrux/src/cosigner/nodesecurity"

	"github.com/stretchr/testify/require"
	"golang.org/x/sync/errgroup"
)

const (
	bitSize = 2048
)

func TestCosignerRSA(t *testing.T) {
	t.Parallel()

	keys := make([]*rsa.PrivateKey, 3)
	pubKeys := make([]*rsa.PublicKey, 3)

	for i := 0; i < 3; i++ {
		key, err := rsa.GenerateKey(rand.Reader, bitSize)
		require.NoError(t, err)

		keys[i] = key
		pubKeys[i] = &key.PublicKey
	}

	securities := make([]*nodesecurity.CosignerSecurityRSA, 3)

	for i := 0; i < 3; i++ {
		key := nodesecurity.CosignerRSAKey{
			ID:      i + 1,
			RSAKey:  *keys[i],
			RSAPubs: pubKeys,
		}
		securities[i] = nodesecurity.NewCosignerSecurityRSA(key)

		bz, err := json.Marshal(&key)
		require.NoError(t, err)

		var key2 nodesecurity.CosignerRSAKey
		require.NoError(t, json.Unmarshal(bz, &key2))
		require.Equal(t, key, key2)

		require.Equal(t, key.RSAKey.N.Bytes(), key2.RSAKey.N.Bytes())
		require.Equal(t, key.RSAKey.D.Bytes(), key2.RSAKey.D.Bytes())
		require.Equal(t, key.RSAKey.E, key2.RSAKey.E)

		for i := 0; i < 3; i++ {
			require.Equal(t, key.RSAPubs[i].N.Bytes(), key2.RSAPubs[i].N.Bytes())
			require.Equal(t, key.RSAPubs[i].E, key2.RSAPubs[i].E)
		}
	}

	err := testCosignerSecurityRSA(t, securities)
	require.ErrorIs(t, rsa.ErrDecryption, err)
}

func TestConcurrentIterateCosignerRSA(t *testing.T) {
	keys := make([]*rsa.PrivateKey, 3)
	pubKeys := make([]*rsa.PublicKey, 3)

	for i := 0; i < 3; i++ {
		key, err := rsa.GenerateKey(rand.Reader, bitSize)
		require.NoError(t, err)

		keys[i] = key
		pubKeys[i] = &key.PublicKey
	}

	securities := make([]cosigner.ICosignerSecurity, 3)

	for i := 0; i < 3; i++ {
		securities[i] = nodesecurity.NewCosignerSecurityRSA(nodesecurity.CosignerRSAKey{
			ID:      i + 1,
			RSAKey:  *keys[i],
			RSAPubs: pubKeys,
		})
	}

	for i := 0; i < 100; i++ {
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
