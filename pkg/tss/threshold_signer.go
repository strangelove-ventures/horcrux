package tss

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/cometbft/cometbft/privval"
)

// LoadVaultKeyFromFile loads the persistent ThresholdSignerKey from file.

func LoadVaultKeyFromFile(file string) (Ed25519Key, error) {
	//pvKey := VaultKey{}
	var pvKey Ed25519Key
	keyJSONBytes, err := os.ReadFile(file)
	if err != nil || len(keyJSONBytes) == 0 {
		fmt.Printf("Could not read key from file %s", file)
		return pvKey, err
	}

	fmt.Printf("keyJsonBytes is: %s", keyJSONBytes)

	err = json.Unmarshal(keyJSONBytes, &pvKey)
	if err != nil {
		fmt.Printf("Could not unmarshal key from file %s", file)
		return pvKey, err
	}

	return pvKey, nil
}

type ChainPrivate interface {
	privval.FilePVKey
}

// type Handler[VPK VaultPrivateKey, CP ChainPrivate] func(CP, uint8, uint8) []VPK
// type ChainHandler[CP ChainPrivate] func(string) (CP, error)

type fn func(privval.FilePVKey, uint8, uint8) []Ed25519Key

// CreatePersistentEd25519ThresholdSignShardsFromFile creates Ed25519Key objects from a priv_validator_key.json file
func CreatePersistentEd25519ThresholdSignShardsFromFile(filename string, threshold, shards uint8) ([]VaultKey, error) {
	pv, err := ReadCometBFTPrivValidatorFile(filename)
	if err != nil {
		fmt.Printf("Could not create shard from file %s", filename)
		return nil, err
	}

	persistentKeys, err := generatePersistentThresholdSignShards(pv, CreateEd25519ThresholdSignShards, threshold, shards)
	return persistentKeys, err

}

// CreatePersistentThresholdSignShardsFromFile creates   objects from a priv_validator_key.json file
func generatePersistentThresholdSignShards(filePVKey privval.FilePVKey, function fn, threshold uint8, shards uint8) ([]VaultKey, error) {
	keys := function(filePVKey, threshold, shards)
	// Transform ed25519Keys to VaultKey type
	vaultKeys := make([]VaultKey, len(keys))
	for i, key := range keys {
		vaultKeys[i] = VaultKey{
			PubKey:       key.PubKey,
			PrivateShard: key.PrivateShard,
			ID:           key.ID,
		}
	}
	return vaultKeys, nil
}
