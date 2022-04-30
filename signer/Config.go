package signer

import (
	"fmt"
	"os"

	"github.com/cosmos/cosmos-sdk/codec"
	"github.com/cosmos/cosmos-sdk/codec/legacy"
	"github.com/cosmos/cosmos-sdk/codec/types"
	cryptocodec "github.com/cosmos/cosmos-sdk/crypto/codec"
	"github.com/cosmos/cosmos-sdk/crypto/keys/ed25519"
	cryptotypes "github.com/cosmos/cosmos-sdk/crypto/types"
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

func PubKey(bech32BasePrefix string, pubKey crypto.PubKey) (string, error) {
	if bech32BasePrefix != "" {
		pubkey, err := cryptocodec.FromTmPubKeyInterface(pubKey)
		if err != nil {
			return "", err
		}
		consPubPrefix := bech32BasePrefix + "valconspub"
		pubKeyBech32, err := bech32.ConvertAndEncode(consPubPrefix, legacy.Cdc.Amino.MustMarshalBinaryBare(pubkey))
		if err != nil {
			return "", err
		}
		return pubKeyBech32, nil
	}

	registry := types.NewInterfaceRegistry()
	marshaler := codec.NewProtoCodec(registry)
	var pk *cryptotypes.PubKey
	registry.RegisterInterface("cosmos.crypto.PubKey", pk)
	registry.RegisterImplementations(pk, &ed25519.PubKey{})
	sdkPK, err := cryptocodec.FromTmPubKeyInterface(pubKey)
	if err != nil {
		return "", err
	}
	pubKeyJSON, err := marshaler.MarshalInterfaceJSON(sdkPK)
	if err != nil {
		return "", err
	}
	return string(pubKeyJSON), nil
}
