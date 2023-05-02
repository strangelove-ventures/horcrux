package signer

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"os"

	cometjson "github.com/cometbft/cometbft/libs/json"
	"github.com/cometbft/cometbft/privval"
	tsed25519 "gitlab.com/unit410/threshold-ed25519/pkg"
)

// CreateCosignerSharesFromFile creates cosigner key objects from a priv_validator_key.json file
func CreateCosignerSharesFromFile(priv string, threshold, shares uint8) ([]CosignerKey, error) {
	pv, err := ReadPrivValidatorFile(priv)
	if err != nil {
		return nil, err
	}
	return CreateCosignerShares(pv, threshold, shares)
}

// CreateCosignerShares creates cosigner key objects from a privval.FilePVKey
func CreateCosignerShares(pv privval.FilePVKey, threshold, shares uint8) (out []CosignerKey, err error) {
	privshares := tsed25519.DealShares(tsed25519.ExpandSecret(pv.PrivKey.Bytes()[:32]), uint8(threshold), uint8(shares))
	for idx, share := range privshares {
		out = append(out, CosignerKey{
			PubKey:   pv.PubKey,
			ShareKey: share,
			ID:       idx + 1,
		})
	}
	return out, nil
}

// CreateCosignerShares creates cosigner key objects from a privval.FilePVKey
func CreateCosignerSharesRSA(shares int) (out []CosignerKeyRSA, err error) {
	rsaKeys, pubKeys, err := makeRSAKeys(shares)
	if err != nil {
		return nil, err
	}
	for i, key := range rsaKeys {
		out = append(out, CosignerKeyRSA{
			ID:           i + 1,
			RSAKey:       *key,
			CosignerKeys: pubKeys,
		})
	}
	return out, nil
}

// ReadPrivValidatorFile reads in a privval.FilePVKey from a given file
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

// WriteCosignerShareFile writes a cosigner key to a given file name
func WriteCosignerShareFile(cosigner CosignerKey, file string) error {
	jsonBytes, err := json.Marshal(&cosigner)
	if err != nil {
		return err
	}
	return os.WriteFile(file, jsonBytes, 0600)
}

// WriteCosignerShareRSAFile writes a cosigner RSA key to a given file name
func WriteCosignerShareRSAFile(cosigner CosignerKeyRSA, file string) error {
	jsonBytes, err := json.Marshal(&cosigner)
	if err != nil {
		return err
	}
	return os.WriteFile(file, jsonBytes, 0600)
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
