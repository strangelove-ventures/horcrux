package signer

import (
	"encoding/json"
	"os"
)

// CosignerKey is a single key shard for an m-of-n threshold signer.
type CosignerKey struct {
	KeyType      string `json:"keyType"`
	PubKey       []byte `json:"pubKey"`
	PrivateShard []byte `json:"privateShard"`
	ID           int    `json:"id"`
}

// LoadCosignerKey loads a CosignerKey from file.
func LoadCosignerKey(file string) (CosignerKey, error) {
	pvKey := CosignerKey{}
	keyJSONBytes, err := os.ReadFile(file)
	if err != nil {
		return pvKey, err
	}

	err = json.Unmarshal(keyJSONBytes, &pvKey)
	if err != nil {
		return pvKey, err
	}

	return pvKey, nil
}
