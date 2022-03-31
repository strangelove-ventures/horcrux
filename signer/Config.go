package signer

import (
	"encoding/base64"
	"fmt"
	"os"

	"github.com/cosmos/cosmos-sdk/codec/legacy"
	cryptocodec "github.com/cosmos/cosmos-sdk/crypto/codec"
	"github.com/cosmos/cosmos-sdk/types/bech32"
	"github.com/tendermint/tendermint/crypto"
)

type NodeConfig struct {
	Address string
}

type CosignerConfig struct {
	ID      int
	Address string
}

type Config struct {
	Mode              string
	PrivValKeyFile    string
	PrivValStateDir   string
	ChainID           string
	CosignerThreshold int
	ListenAddress     string
	Nodes             []NodeConfig
	Cosigners         []CosignerConfig
}

func (cfg *Config) KeyFileExists() error {
	if _, err := os.Stat(cfg.PrivValKeyFile); os.IsNotExist(err) {
		return fmt.Errorf("private key share doesn't exist at path(%s)", cfg.PrivValKeyFile)
	}
	return nil
}

func PubKey(bech32BasePrefix string, pubKey crypto.PubKey) string {
	if bech32BasePrefix != "" {
		pubkey, err := cryptocodec.FromTmPubKeyInterface(pubKey)
		if err != nil {
			return ""
		}
		consPubPrefix := bech32BasePrefix + "valconspub"
		pubKeyBech32, err := bech32.ConvertAndEncode(consPubPrefix, legacy.Cdc.Amino.MustMarshalBinaryBare(pubkey))
		if err != nil {
			return ""
		}
		return pubKeyBech32
	}

	sEnc := base64.StdEncoding.EncodeToString(pubKey.Bytes())
	return fmt.Sprintf("{\"@type\":\"/cosmos.crypto.ed25519.PubKey\",\"key\":\"%s\"}", sEnc)
}
