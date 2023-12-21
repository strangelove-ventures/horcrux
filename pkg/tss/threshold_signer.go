package tss

import (
	"encoding/json"
	"os"

	"github.com/cometbft/cometbft/privval"
	tsed25519 "gitlab.com/unit410/threshold-ed25519/pkg"
)

// LoadThresholdSignerEd25519Key loads the persistent ThresholdSignerEd25519Key from file.
func LoadThresholdSignerEd25519Key(file string) (CosignerEd25519Key, error) {
	pvKey := CosignerEd25519Key{}
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

// CreateEd25519ThresholdSignShardsFromFile creates CosignerEd25519Key objects from a priv_validator_key.json file
func CreateEd25519ThresholdSignShardsFromFile(priv string, threshold, shards uint8) ([]CosignerEd25519Key, error) {
	pv, err := ReadPrivValidatorFile(priv)
	if err != nil {
		return nil, err
	}
	return CreateEd25519ThresholdSignShards(pv, threshold, shards), nil
}

// CreateEd25519ThresholdSignShards creates CosignerEd25519Key objects from a privval.FilePVKey
func CreateEd25519ThresholdSignShards(pv privval.FilePVKey, threshold, shards uint8) []CosignerEd25519Key {
	privShards := tsed25519.DealShares(tsed25519.ExpandSecret(pv.PrivKey.Bytes()[:32]), threshold, shards)
	out := make([]CosignerEd25519Key, shards)
	for i, shard := range privShards {
		out[i] = CosignerEd25519Key{
			PubKey:       pv.PubKey,
			PrivateShard: shard,
			ID:           i + 1,
		}
	}
	return out
}
