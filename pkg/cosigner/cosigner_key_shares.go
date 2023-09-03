package cosigner

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"os"

	cometjson "github.com/cometbft/cometbft/libs/json"
	"github.com/cometbft/cometbft/privval"
	"github.com/ethereum/go-ethereum/crypto/ecies"
	"github.com/ethereum/go-ethereum/crypto/secp256k1"
	tsed25519 "gitlab.com/unit410/threshold-ed25519/pkg"
	"golang.org/x/sync/errgroup"
)

// CreateCosignerEd25519ShardsFromFile creates CosignEd25519Key objects from a priv_validator_key.json file
func CreateCosignerEd25519ShardsFromFile(priv string, threshold, shards uint8) ([]CosignEd25519Key, error) {
	pv, err := ReadPrivValidatorFile(priv)
	if err != nil {
		return nil, err
	}
	return CreateCosignerEd25519Shards(pv, threshold, shards), nil
}

// CreateCosignerEd25519Shards creates CosignEd25519Key objects from a privval.FilePVKey
// by splitting the secret using Shamir secret sharing.
func CreateCosignerEd25519Shards(pv privval.FilePVKey, threshold, shards uint8) []CosignEd25519Key {
	// tsed25519.DealShares splits the secret using Shamir Secret Sharing (Note its: no verifiable secret sharing)
	// privshards is shamir shares
	privShards := tsed25519.DealShares(tsed25519.ExpandSecret(pv.PrivKey.Bytes()[:32]), threshold, shards)
	out := make([]CosignEd25519Key, shards)
	for i, shard := range privShards {
		out[i] = CosignEd25519Key{
			PubKey:       pv.PubKey,
			PrivateShard: shard,
			ID:           i + 1,
		}
	}
	return out
}

// CreateCosignerRSAShards generate  CosignRSAKey objects.
func CreateCosignerRSAShards(shards int) ([]CosignRSAKey, error) {
	rsaKeys, pubKeys, err := makeRSAKeys(shards)
	if err != nil {
		return nil, err
	}
	out := make([]CosignRSAKey, shards)
	for i, key := range rsaKeys {
		out[i] = CosignRSAKey{
			ID:      i + 1,
			RSAKey:  *key,
			RSAPubs: pubKeys,
		}
	}
	return out, nil
}

// ReadPrivValidatorFile reads in a privval.FilePVKey from a given file.
func ReadPrivValidatorFile(priv string) (out privval.FilePVKey, err error) {
	var bz []byte
	if bz, err = os.ReadFile(priv); err != nil {
		return
	}
	if err = cometjson.Unmarshal(bz, &out); err != nil {
		return
	}
	return
}

// WriteCosignerEd25519ShardFile writes a cosigner Ed25519 key to a given file name.
func WriteCosignerEd25519ShardFile(cosigner CosignEd25519Key, file string) error {
	jsonBytes, err := json.Marshal(&cosigner)
	if err != nil {
		return err
	}
	return os.WriteFile(file, jsonBytes, 0600)
}

// WriteCosignerRSAShardFile writes a cosigner RSA key to a given file name.
func WriteCosignerRSAShardFile(cosigner CosignRSAKey, file string) error {
	jsonBytes, err := json.Marshal(&cosigner)
	if err != nil {
		return err
	}
	return os.WriteFile(file, jsonBytes, 0600)
}

// CreateCosignerECIESShards generates CosignEciesKey objects.
func CreateCosignerECIESShards(shards int) ([]CosignEciesKey, error) {
	eciesKeys, pubKeys, err := makeECIESKeys(shards)
	if err != nil {
		return nil, err
	}
	out := make([]CosignEciesKey, shards)
	for i, key := range eciesKeys {
		out[i] = CosignEciesKey{
			ID:        i + 1,
			ECIESKey:  key,
			ECIESPubs: pubKeys,
		}
	}
	return out, nil
}

// WriteCosignECIESShardFile writes a cosigner ECIES key to a given file name.
func WriteCosignECIESShardFile(cosigner CosignEciesKey, file string) error {
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
