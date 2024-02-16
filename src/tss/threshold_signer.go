package tss

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/cometbft/cometbft/privval"
	"github.com/strangelove-ventures/horcrux/src/config"
	"github.com/strangelove-ventures/horcrux/src/tss/tss25519"

	cometbytes "github.com/cometbft/cometbft/libs/bytes"
)

type Address = cometbytes.HexBytes

type PubKey interface {
	Address() Address
	Bytes() []byte
	VerifySignature(msg []byte, sig []byte) bool
	// Equals(PubKey) bool
	Type() string
}

func NewThresholdEd25519SignerSoft(config *config.RuntimeConfig, id int, chainID string) (*tss25519.SignerSoft, error) {
	keyFile, err := config.KeyFileExistsCosigner(chainID)
	if err != nil {
		return nil, err
	}

	key, err := LoadVaultKeyFromFile(keyFile)
	if err != nil {
		return nil, fmt.Errorf("error reading Vault key: %s", err)
	}

	if key.ID != id {
		return nil, fmt.Errorf("key shard Index (%d) in (%s) does not match cosigner Index (%d)", key.ID, keyFile, id)
	}
	return tss25519.NewSignerSoft(
		key.PrivateShard,
		key.PubKey.Bytes(),
		uint8(config.Config.ThresholdModeConfig.Threshold),
		uint8(len(config.Config.ThresholdModeConfig.Cosigners)),
		uint8(key.ID),
	)
}

// LoadVaultKeyFromFile loads the persistent ThresholdSignerKey from file.

func LoadVaultKeyFromFile(file string) (Ed25519Key, error) {
	// pvKey := VaultKey{}
	var pvKey Ed25519Key
	keyJSONBytes, err := os.ReadFile(file)
	if err != nil || len(keyJSONBytes) == 0 {
		fmt.Printf("Could not read key from file %s", file)
		return pvKey, err
	}

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
type fn func([]byte, uint8, uint8) map[uint8][]byte

// ted25519.GenerateEd25519ThresholdSignShards()

// CreatePersistentEd25519ThresholdSignShardsFromFile creates Ed25519Key objects from a priv_validator_key.json file
func CreatePersistentEd25519ThresholdSignShardsFromFile(filename string, threshold, shards uint8) ([]VaultKey, error) {
	pv, err := ReadCometBFTPrivValidatorFile(filename)
	if err != nil {
		fmt.Printf("Could not create shard from file %s", filename)
		return nil, err
	}

	pubkey := pv.PubKey.(PubKey)
	persistentKeys, err := generatePersistentThresholdSignShards(pv.PrivKey.Bytes(), pubkey, tss25519.GenerateSignatureShards, threshold, shards)
	return persistentKeys, err

}

func GeneratePersistentThresholdSignShards[Key Ed25519Key](privateKey []byte, publicKey PubKey, threshold uint8, shards uint8) ([]Key, error) {
	keys := tss25519.GenerateSignatureShards(privateKey, threshold, shards)
	// Transform ed25519Keys to VaultKey type

	vaultKeys := make([]Key, len(keys))
	for id, key := range keys {
		vaultKeys[id-1] = Key{
			PubKey:       publicKey,
			PrivateShard: key,
			ID:           int(id),
		}
	}
	return vaultKeys, nil
}

// CreatePersistentThresholdSignShardsFromFile creates   objects from a priv_validator_key.json file
func generatePersistentThresholdSignShards(privateKey []byte, publicKey PubKey, function fn, threshold uint8, shards uint8) ([]VaultKey, error) {
	keys := function(privateKey, threshold, shards)
	// Transform ed25519Keys to VaultKey type
	vaultKeys := make([]VaultKey, len(keys))

	fmt.Printf("Number of keys to create: %d\n", len(keys))
	for id, key := range keys {
		fmt.Printf("VaultKey: %d\n", id)
		vaultKeys[id-1] = VaultKey{
			PubKey:       publicKey,
			PrivateShard: key,
			ID:           int(id),
		}
	}
	return vaultKeys, nil
}
