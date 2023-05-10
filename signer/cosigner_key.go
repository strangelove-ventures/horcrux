package signer

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"os"

	cometcrypto "github.com/cometbft/cometbft/crypto"
	cometcryptoed25519 "github.com/cometbft/cometbft/crypto/ed25519"
	cometcryptoencoding "github.com/cometbft/cometbft/crypto/encoding"
	cometprotocrypto "github.com/cometbft/cometbft/proto/tendermint/crypto"
	amino "github.com/tendermint/go-amino"
)

// CosignerEd25519Key is a single Ed255219 key shard for an m-of-n threshold signer.
type CosignerEd25519Key struct {
	PubKey       cometcrypto.PubKey `json:"pubKey"`
	PrivateShard []byte             `json:"privateShard"`
	ID           int                `json:"id"`
}

func (key *CosignerEd25519Key) MarshalJSON() ([]byte, error) {
	type Alias CosignerEd25519Key

	protoPubkey, err := cometcryptoencoding.PubKeyToProto(key.PubKey)
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

func (key *CosignerEd25519Key) UnmarshalJSON(data []byte) error {
	type Alias CosignerEd25519Key

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

	key.PubKey = pubkey
	return nil
}

// LoadCosignerEd25519Key loads a CosignerEd25519Key from file.
func LoadCosignerEd25519Key(file string) (CosignerEd25519Key, error) {
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

// CosignerEd25519Key is a single RSA key for an m-of-n threshold signer.
type CosignerRSAKey struct {
	RSAKey  rsa.PrivateKey   `json:"rsaKey"`
	ID      int              `json:"id"`
	RSAPubs []*rsa.PublicKey `json:"rsaPubs"`
}

func (key *CosignerRSAKey) MarshalJSON() ([]byte, error) {
	type Alias CosignerRSAKey

	// marshal our private key and all public keys
	privateBytes := x509.MarshalPKCS1PrivateKey(&key.RSAKey)
	rsaPubKeysBytes := make([][]byte, 0)
	for _, pubKey := range key.RSAPubs {
		publicBytes := x509.MarshalPKCS1PublicKey(pubKey)
		rsaPubKeysBytes = append(rsaPubKeysBytes, publicBytes)
	}

	return json.Marshal(&struct {
		RSAKey  []byte   `json:"rsaKey"`
		RSAPubs [][]byte `json:"rsaPubs"`
		*Alias
	}{
		RSAKey:  privateBytes,
		RSAPubs: rsaPubKeysBytes,
		Alias:   (*Alias)(key),
	})
}

func (key *CosignerRSAKey) UnmarshalJSON(data []byte) error {
	type Alias CosignerRSAKey

	aux := &struct {
		RSAKey  []byte   `json:"rsaKey"`
		RSAPubs [][]byte `json:"rsaPubs"`
		*Alias
	}{
		Alias: (*Alias)(key),
	}
	if err := json.Unmarshal(data, &aux); err != nil {
		return err
	}
	privateKey, err := x509.ParsePKCS1PrivateKey(aux.RSAKey)
	if err != nil {
		return err
	}

	// unmarshal the public key bytes for each cosigner
	key.RSAPubs = make([]*rsa.PublicKey, 0)
	for _, bytes := range aux.RSAPubs {
		cosignerRsaPubkey, err := x509.ParsePKCS1PublicKey(bytes)
		if err != nil {
			return err
		}
		key.RSAPubs = append(key.RSAPubs, cosignerRsaPubkey)
	}

	key.RSAKey = *privateKey
	return nil
}

// LoadCosignerRSAKey loads a CosignerRSAKey from file.
func LoadCosignerRSAKey(file string) (CosignerRSAKey, error) {
	pvKey := CosignerRSAKey{}
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
