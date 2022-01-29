package signer

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"io/ioutil"

	tmjson "github.com/tendermint/tendermint/libs/json"
	"github.com/tendermint/tendermint/privval"
	tsed25519 "gitlab.com/polychainlabs/threshold-ed25519/pkg"
)

// CreateCosignerSharesFromFile creates cosigner key objects from a priv_validator_key.json file
func CreateCosignerSharesFromFile(priv string, threshold, shares int64) ([]CosignerKey, error) {
	pv, err := ReadPrivValidatorFile(priv)
	if err != nil {
		return nil, err
	}
	return CreateCosignerShares(pv, threshold, shares)
}

// CreateCosignerShares creates cosigner key objects from a privval.FilePVKey
func CreateCosignerShares(pv privval.FilePVKey, threshold, shares int64) (out []CosignerKey, err error) {
	privshares := tsed25519.DealShares(tsed25519.ExpandSecret(pv.PrivKey.Bytes()[:32]), uint8(threshold), uint8(shares))
	rsaKeys, pubKeys, err := makeRSAKeys(len(privshares))
	if err != nil {
		return nil, err
	}
	for idx, share := range privshares {
		out = append(out, CosignerKey{
			PubKey:       pv.PubKey,
			ShareKey:     share,
			ID:           idx + 1,
			RSAKey:       *rsaKeys[idx],
			CosignerKeys: pubKeys,
		})
	}
	return
}

// ReadPrivValidatorFile reads in a privval.FilePVKey from a given file
func ReadPrivValidatorFile(priv string) (out privval.FilePVKey, err error) {
	var bz []byte
	if bz, err = ioutil.ReadFile(priv); err != nil {
		return
	}
	if err = tmjson.Unmarshal(bz, &out); err != nil {
		return
	}
	return
}

// WriteCosignerShareFile writes a cosigner key to a given file name
func WriteCosignerShareFile(cosigner CosignerKey, file string) error {
	jsonBytes, err := json.Marshal(&cosigner)
	if err != nil {
		return err
	}
	return ioutil.WriteFile(file, jsonBytes, 0644) //nolint
}

func makeRSAKeys(num int) (rsaKeys []*rsa.PrivateKey, pubKeys []*rsa.PublicKey, err error) {
	rsaKeys = make([]*rsa.PrivateKey, num)
	pubKeys = make([]*rsa.PublicKey, num)
	for i := 0; i < num; i++ {
		bitSize := 4096
		rsaKey, err := rsa.GenerateKey(rand.Reader, bitSize)
		if err != nil {
			return rsaKeys, pubKeys, err
		}
		rsaKeys[i] = rsaKey
		pubKeys[i] = &rsaKey.PublicKey
	}
	return
}
