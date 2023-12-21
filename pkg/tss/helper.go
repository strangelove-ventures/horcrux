package thresholdTemP

import (
	"encoding/json"
	"os"
)

type Privatekey interface {
	PersistentEd25519Key | CosignerEd25519Key
}

func WritePrivateKeyToFile[PK Privatekey](privateshare PK, file string) error {
	jsonBytes, err := json.Marshal(&privateshare)
	if err != nil {
		return err
	}
	return os.WriteFile(file, jsonBytes, 0600)
}
