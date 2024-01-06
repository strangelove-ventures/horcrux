package nodesecurity

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"os"

	"github.com/ethereum/go-ethereum/crypto/ecies"
	"github.com/ethereum/go-ethereum/crypto/secp256k1"
	"golang.org/x/sync/errgroup"
)

// CreateCosignerRSAShards generate  CosignerRSAKey objects.
func CreateCosignerRSAShards(shards int) ([]CosignerRSAKey, error) {
	rsaKeys, pubKeys, err := makeRSAKeys(shards)
	if err != nil {
		return nil, err
	}
	out := make([]CosignerRSAKey, shards)
	for i, key := range rsaKeys {
		out[i] = CosignerRSAKey{
			ID:      i + 1,
			RSAKey:  *key,
			RSAPubs: pubKeys,
		}
	}
	return out, nil
}

// WriteCosignerRSAShardFile writes a cosigner RSA key to a given file name.
func WriteCosignerRSAShardFile(cosigner CosignerRSAKey, file string) error {
	jsonBytes, err := json.Marshal(&cosigner)
	if err != nil {
		return err
	}
	return os.WriteFile(file, jsonBytes, 0600)
}

// CreateCosignerECIESShards generates CosignerECIESKey objects.
func CreateCosignerECIESShards(shards int) ([]CosignerECIESKey, error) {
	eciesKeys, pubKeys, err := makeECIESKeys(shards)
	if err != nil {
		return nil, err
	}
	out := make([]CosignerECIESKey, shards)
	for i, key := range eciesKeys {
		out[i] = CosignerECIESKey{
			ID:        i + 1,
			ECIESKey:  key,
			ECIESPubs: pubKeys,
		}
	}
	return out, nil
}

// WriteCosignerECIESShardFile writes a cosigner ECIES key to a given file name.
func WriteCosignerECIESShardFile(cosigner CosignerECIESKey, file string) error {
	jsonBytes, err := json.Marshal(&cosigner)
	if err != nil {
		return err
	}
	return os.WriteFile(file, jsonBytes, 0600)
}

func makeRSAKeys(num int) (rsaKeys []*rsa.PrivateKey, pubKeys []*rsa.PublicKey, err error) {
	rsaKeys = make([]*rsa.PrivateKey, num)
	pubKeys = make([]*rsa.PublicKey, num)
	var eg errgroup.Group
	bitSize := 4096
	for i := 0; i < num; i++ {
		i := i
		eg.Go(func() error {
			rsaKey, err := rsa.GenerateKey(rand.Reader, bitSize)
			if err != nil {
				return err
			}
			rsaKeys[i] = rsaKey
			pubKeys[i] = &rsaKey.PublicKey

			return nil
		})
	}
	return rsaKeys, pubKeys, eg.Wait()
}

func makeECIESKeys(num int) ([]*ecies.PrivateKey, []*ecies.PublicKey, error) {
	eciesKeys := make([]*ecies.PrivateKey, num)
	pubKeys := make([]*ecies.PublicKey, num)
	var eg errgroup.Group
	for i := 0; i < num; i++ {
		i := i
		eg.Go(func() error {
			eciesKey, err := ecies.GenerateKey(rand.Reader, secp256k1.S256(), nil)
			if err != nil {
				return err
			}
			eciesKeys[i] = eciesKey
			pubKeys[i] = &eciesKey.PublicKey
			return nil
		})
	}
	return eciesKeys, pubKeys, eg.Wait()
}
