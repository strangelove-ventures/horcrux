package signer

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"

	cometcrypto "github.com/strangelove-ventures/horcrux/v3/comet/crypto"
	cometcryptobn254 "github.com/strangelove-ventures/horcrux/v3/comet/crypto/bn254"
	cometcryptoed25519 "github.com/strangelove-ventures/horcrux/v3/comet/crypto/ed25519"
	"github.com/strangelove-ventures/horcrux/v3/comet/encoding"
	cometprotocrypto "github.com/strangelove-ventures/horcrux/v3/comet/proto/crypto"

	"github.com/tendermint/go-amino"
)

// CosignerKey is a single key shard for an m-of-n threshold signer.
type CosignerKey struct {
	KeyType      string `json:"keyType"`
	PubKey       []byte `json:"pubKey"`
	PrivateShard []byte `json:"privateShard"`
	ID           int    `json:"id"`
}

func (key *CosignerKey) MarshalJSON() ([]byte, error) {
	type Alias CosignerKey

	var pub cometcrypto.PubKey
	switch key.KeyType {
	case CosignerKeyTypeBn254:
		pub = cometcryptobn254.PubKey(key.PubKey)
	case CosignerKeyTypeEd25519:
		fallthrough
	default:
		pub = cometcryptoed25519.PubKey(key.PubKey)
	}

	protoPubkey, err := encoding.PubKeyToProto(pub)
	if err != nil {
		return nil, err
	}

	protoBytes, err := protoPubkey.Marshal()
	if err != nil {
		return nil, err
	}

	return json.Marshal(&struct {
		PubKey []byte `json:"pubKey"`
		*Alias
	}{
		PubKey: protoBytes,
		Alias:  (*Alias)(key),
	})
}

func (key *CosignerKey) UnmarshalJSON(data []byte) error {
	type Alias CosignerKey

	aux := &struct {
		PubkeyBytes []byte `json:"pubKey"`
		*Alias
	}{
		Alias: (*Alias)(key),
	}
	if err := json.Unmarshal(data, &aux); err != nil {
		return err
	}

	var pubkey cometcrypto.PubKey
	var protoPubkey cometprotocrypto.PublicKey
	err := protoPubkey.Unmarshal(aux.PubkeyBytes)

	// Prior to the tendermint protobuf migration, the public key bytes in key files
	// were encoded using the go-amino libraries via
	// cdc.MarshalBinaryBare(key.PubKey)
	//
	// To support reading the public key bytes from these key files, we fallback to
	// amino unmarshalling if the protobuf unmarshalling fails
	if err != nil {
		codec := amino.NewCodec()
		codec.RegisterInterface((*cometcrypto.PubKey)(nil), nil)
		codec.RegisterConcrete(cometcryptoed25519.PubKey{}, "tendermint/PubKeyEd25519", nil)

		var pub cometcryptoed25519.PubKey
		if errInner := codec.UnmarshalBinaryBare(aux.PubkeyBytes, &pub); errInner != nil {
			return fmt.Errorf("error in unmarshal ed25519: %w", errors.Join(err, errInner))
		}
		pubkey = pub
	} else {
		pubkey, err = encoding.PubKeyFromProto(protoPubkey)
		if err != nil {
			return err
		}
	}

	switch pubkey.(type) {
	case cometcryptobn254.PubKey:
		key.KeyType = CosignerKeyTypeBn254
	case cometcryptoed25519.PubKey:
		key.KeyType = CosignerKeyTypeEd25519
	default:
		return fmt.Errorf("unsupported key type: %T", pubkey)
	}

	key.PubKey = pubkey.Bytes()
	return nil
}

// LoadCosignerKey loads a CosignerKey from file.
func LoadCosignerKey(file string) (*CosignerKey, error) {
	pvKey := new(CosignerKey)
	keyJSONBytes, err := os.ReadFile(file)
	if err != nil {
		return pvKey, err
	}

	err = json.Unmarshal(keyJSONBytes, &pvKey)
	if err != nil {
		return pvKey, fmt.Errorf("error in unmarshal: %w", err)
	}

	return pvKey, nil
}
