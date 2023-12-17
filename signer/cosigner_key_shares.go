package signer

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"errors"
	"fmt"
	"os"

	"github.com/ethereum/go-ethereum/crypto/ecies"
	"github.com/ethereum/go-ethereum/crypto/secp256k1"
	tsed25519 "gitlab.com/unit410/threshold-ed25519/pkg"
	"go.dedis.ch/kyber/v3/pairing/bn256"
	"go.dedis.ch/kyber/v3/share"
	"golang.org/x/sync/errgroup"
)

var ErrUnsupportedKeyType = errors.New("unsupported key type")

// CreateCosignerEd25519ShardsFromFile creates CosignerKey objects from a priv_validator_key.json file
func CreateCosignerShardsFromFile(priv string, threshold, shards uint8) ([]CosignerKey, error) {
	pv, err := ReadPrivValidatorFile(priv)
	if err != nil {
		return nil, err
	}

	switch pv.PrivKey.Type {
	case "tendermint/PrivKeyEd25519":
		return CreateCosignerEd25519Shards(pv, threshold, shards), nil
	case "tendermint/PrivKeyBn254":
		return CreateCosignerBn254Shards(pv, threshold, shards), nil
	default:
		return nil, ErrUnsupportedKeyType
	}
}

// CreateCosignerEd25519Shards creates CosignerKey objects from a privval.FilePVKey
func CreateCosignerEd25519Shards(pv *TMPrivvalFile, threshold, shards uint8) []CosignerKey {
	fmt.Printf("ED25519 pv.PrivKey.Value: %v, len: %d\n", pv.PrivKey.Value, len(pv.PrivKey.Value))
	privShards := tsed25519.DealShares(tsed25519.ExpandSecret(pv.PrivKey.Value[:32]), threshold, shards)
	out := make([]CosignerKey, shards)
	for i, shard := range privShards {
		out[i] = CosignerKey{
			KeyType:      CosignerKeyTypeEd25519,
			PubKey:       pv.PubKey.Value,
			PrivateShard: shard,
			ID:           i + 1,
		}
	}
	return out
}

// CreateCosignerEd25519Shards creates CosignerKey objects from a privval.FilePVKey
func CreateCosignerBn254Shards(pv *TMPrivvalFile, threshold, shards uint8) []CosignerKey {
	fmt.Printf("BN254 pv.PrivKey.Value: %v, len: %d\n", pv.PrivKey.Value, len(pv.PrivKey.Value))
	suite := bn256.NewSuite()
	secret := suite.G1().Scalar().SetBytes(pv.PrivKey.Value)
	priPoly := share.NewPriPoly(suite.G2(), int(threshold), secret, suite.RandomStream())
	privShards := priPoly.Shares(int(shards))

	out := make([]CosignerKey, shards)
	for i, shard := range privShards {
		v, err := shard.V.MarshalBinary()
		if err != nil {
			panic(err)
		}
		out[i] = CosignerKey{
			KeyType:      CosignerKeyTypeBn254,
			PubKey:       pv.PubKey.Value,
			PrivateShard: v,
			ID:           i + 1,
		}
	}
	return out
}

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

type TMPrivvalFile struct {
	Address string `json:"address"`
	PubKey  struct {
		Type  string `json:"type"`
		Value []byte `json:"value"`
	} `json:"pub_key"`
	PrivKey struct {
		Type  string `json:"type"`
		Value []byte `json:"value"`
	} `json:"priv_key"`
}

// ReadPrivValidatorFile reads in a privval.FilePVKey from a given file.
func ReadPrivValidatorFile(priv string) (*TMPrivvalFile, error) {
	bz, err := os.ReadFile(priv)
	if err != nil {
		return nil, err
	}

	var out TMPrivvalFile

	if err := json.Unmarshal(bz, &out); err != nil {
		return nil, err
	}

	return &out, nil
}

// WriteCosignerShardFile writes a cosigner key shard to a given file name.
func WriteCosignerShardFile(cosigner CosignerKey, file string) error {
	jsonBytes, err := json.Marshal(&cosigner)
	if err != nil {
		return err
	}
	return os.WriteFile(file, jsonBytes, 0600)
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
