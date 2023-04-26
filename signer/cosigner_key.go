package signer

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"os"

	tmcrypto "github.com/cometbft/cometbft/crypto"
	tmcryptoed25519 "github.com/cometbft/cometbft/crypto/ed25519"
	tmcryptoencoding "github.com/cometbft/cometbft/crypto/encoding"
	tmprotocrypto "github.com/cometbft/cometbft/proto/tendermint/crypto"
	amino "github.com/tendermint/go-amino"
)

// CosignerKey is a single key for an m-of-n threshold signer.
type CosignerKey struct {
	PubKey       tmcrypto.PubKey  `json:"pub_key"`
	ShareKey     []byte           `json:"secret_share"`
	RSAKey       rsa.PrivateKey   `json:"rsa_key"`
	ID           int              `json:"id"`
	CosignerKeys []*rsa.PublicKey `json:"rsa_pubs"`
}

func (cosignerKey *CosignerKey) MarshalJSON() ([]byte, error) {
	type Alias CosignerKey

	// marshal our private key and all public keys
	privateBytes := x509.MarshalPKCS1PrivateKey(&cosignerKey.RSAKey)
	rsaPubKeysBytes := make([][]byte, 0)
	for _, pubKey := range cosignerKey.CosignerKeys {
		publicBytes := x509.MarshalPKCS1PublicKey(pubKey)
		rsaPubKeysBytes = append(rsaPubKeysBytes, publicBytes)
	}

	protoPubkey, err := tmcryptoencoding.PubKeyToProto(cosignerKey.PubKey)
	if err != nil {
		return nil, err
	}

	protoBytes, err := protoPubkey.Marshal()
	if err != nil {
		return nil, err
	}

	return json.Marshal(&struct {
		RSAKey       []byte   `json:"rsa_key"`
		Pubkey       []byte   `json:"pub_key"`
		CosignerKeys [][]byte `json:"rsa_pubs"`
		*Alias
	}{
		Pubkey:       protoBytes,
		RSAKey:       privateBytes,
		CosignerKeys: rsaPubKeysBytes,
		Alias:        (*Alias)(cosignerKey),
	})
}

func (cosignerKey *CosignerKey) UnmarshalJSON(data []byte) error {
	type Alias CosignerKey

	aux := &struct {
		RSAKey       []byte   `json:"rsa_key"`
		PubkeyBytes  []byte   `json:"pub_key"`
		CosignerKeys [][]byte `json:"rsa_pubs"`
		*Alias
	}{
		Alias: (*Alias)(cosignerKey),
	}
	if err := json.Unmarshal(data, &aux); err != nil {
		return err
	}
	privateKey, err := x509.ParsePKCS1PrivateKey(aux.RSAKey)
	if err != nil {
		return err
	}

	var pubkey tmcrypto.PubKey
	var protoPubkey tmprotocrypto.PublicKey
	err = protoPubkey.Unmarshal(aux.PubkeyBytes)

	// Prior to the tendermint protobuf migration, the public key bytes in key files
	// were encoded using the go-amino libraries via
	// cdc.MarshalBinaryBare(cosignerKey.PubKey)
	//
	// To support reading the public key bytes from these key files, we fallback to
	// amino unmarshalling if the protobuf unmarshalling fails
	if err != nil {
		var pub tmcryptoed25519.PubKey
		codec := amino.NewCodec()
		codec.RegisterInterface((*tmcrypto.PubKey)(nil), nil)
		codec.RegisterConcrete(tmcryptoed25519.PubKey{}, "tendermint/PubKeyEd25519", nil)
		errInner := codec.UnmarshalBinaryBare(aux.PubkeyBytes, &pub)
		if errInner != nil {
			return err
		}
		pubkey = pub
	} else {
		pubkey, err = tmcryptoencoding.PubKeyFromProto(protoPubkey)
		if err != nil {
			return err
		}
	}

	// unmarshal the public key bytes for each cosigner
	cosignerKey.CosignerKeys = make([]*rsa.PublicKey, 0)
	for _, bytes := range aux.CosignerKeys {
		cosignerRsaPubkey, err := x509.ParsePKCS1PublicKey(bytes)
		if err != nil {
			return err
		}
		cosignerKey.CosignerKeys = append(cosignerKey.CosignerKeys, cosignerRsaPubkey)
	}

	cosignerKey.RSAKey = *privateKey
	cosignerKey.PubKey = pubkey
	return nil
}

// LoadCosignerKey loads a CosignerKey from file.
func LoadCosignerKey(file string) (CosignerKey, error) {
	pvKey := CosignerKey{}
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
