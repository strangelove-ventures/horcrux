package tss

import (
	"encoding/json"
	"os"
)

type VaultPrivateKey interface {
	PersistentEd25519Key | CosignerEd25519Key
}

func WritePrivateKeyToFile[VPK VaultPrivateKey](privateshare VPK, file string) error {
	jsonBytes, err := json.Marshal(&privateshare)
	if err != nil {
		return err
	}
	return os.WriteFile(file, jsonBytes, 0600)
}
