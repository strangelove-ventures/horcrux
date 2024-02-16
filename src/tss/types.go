package tss

import (
	"encoding/json"
	"os"

	cometcrypto "github.com/cometbft/cometbft/crypto"
	cometcryptoed25519 "github.com/cometbft/cometbft/crypto/ed25519"
	cometcryptoencoding "github.com/cometbft/cometbft/crypto/encoding"
	cometjson "github.com/cometbft/cometbft/libs/json"
	"github.com/cometbft/cometbft/privval"
	cometprotocrypto "github.com/cometbft/cometbft/proto/tendermint/crypto"
	"github.com/tendermint/go-amino"
)

/*
type ISignerKey interface {
	MarshalJSON() ([]byte, error)
	UnmarshalJSON(data []byte) error
}
*/

// Ed25519Key is a single Ed255219 key shard for an m-of-n threshold signer.
// TODO: This should be renamed to SignerEd25519 and tbh Private shard should private.
type PersistentEd25519Key struct {
	pubKey       PubKey // Public key of the persistent shard. Pubkey is the same for all shards.
	privateShard []byte //
	index        int    // Shamir index of this shard
}

/*
	type Ed25519Key struct {
		PubKey       cometcrypto.PubKey `json:"pubKey"`
		PrivateShard []byte             `json:"privateShard"`
		Id           int                `json:"id"`
	}

// TODO: Should not actually get this.

	func (key *Ed25519Key) ID() int {
		return key.Id
	}
*/

// Public Private

type AssymetricKey struct {
	PubKey       cometcrypto.PubKey `json:"pubKey"`
	PrivateShard []byte             `json:"privateShard"`
}

type AssymetricKeyShard struct {
	AssymetricKey
	ID int `json:"id"` // ID is the Shamir index or this shard.

}

type Ed25519Key struct {
	PubKey       PubKey `json:"pubKey"`
	PrivateShard []byte `json:"privateShard"`
	ID           int    `json:"id"`
}

type VaultKey Ed25519Key

// TODO: redo to a function.
func (key *Ed25519Key) MarshalJSON() ([]byte, error) {
	type Alias Ed25519Key

	protoPubkey, err := cometcryptoencoding.PubKeyToProto(key.PubKey.(cometcrypto.PubKey))
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

func (key *Ed25519Key) UnmarshalJSON(data []byte) error {
	type Alias Ed25519Key

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
		var pub cometcryptoed25519.PubKey
		codec := amino.NewCodec()
		codec.RegisterInterface((*cometcrypto.PubKey)(nil), nil)
		codec.RegisterConcrete(cometcryptoed25519.PubKey{}, "tendermint/PubKeyEd25519", nil)
		errInner := codec.UnmarshalBinaryBare(aux.PubkeyBytes, &pub)
		if errInner != nil {
			return err
		}
		pubkey = pub
	} else {
		pubkey, err = cometcryptoencoding.PubKeyFromProto(protoPubkey)
		if err != nil {
			return err
		}
	}

	key.PubKey = pubkey.(PubKey)
	return nil
}

// ReadCometBFTPrivValidatorFile reads in a Comet privval.FilePVKey from a given file.
func ReadCometBFTPrivValidatorFile(filename string) (out privval.FilePVKey, err error) {
	var bz []byte
	if bz, err = os.ReadFile(filename); err != nil {
		return
	}
	if err = cometjson.Unmarshal(bz, &out); err != nil {
		return
	}
	return
}

func WriteCometBFTPrivValidatorFile(filename string, pv privval.FilePVKey) (err error) {
	var bz []byte
	if bz, err = cometjson.Marshal(pv); err != nil {
		return err
	}
	return os.WriteFile(filename, bz, 0600)
}

type VaultPrivateKey interface {
	Ed25519Key | VaultKey
}

// WriteToFile writes a key structure to a given file name.
//
// It json.Marshal's the key structure and writes the result to to file with the
// 0600 permission.
func WriteToFile[VPK VaultPrivateKey](privateshare VPK, file string) error {
	jsonBytes, err := json.Marshal(&privateshare)
	if err != nil {
		return err
	}
	return os.WriteFile(file, jsonBytes, 0600)
}
