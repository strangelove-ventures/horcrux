package signer

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"os"

	cometjson "github.com/cometbft/cometbft/libs/json"
	ecies "github.com/ecies/go/v2"
	"golang.org/x/sync/errgroup"
)

var _ CosignerSecurity = &CosignerSecurityECIES{}

// CosignerSecurityECIES is an implementation of CosignerSecurity
// using ECIES for encryption and ECDSA for digital signature.
type CosignerSecurityECIES struct {
	key          CosignerECIESKey
	eciesPubKeys map[int]CosignerECIESPubKey
}

// CosignerECIESKey is a cosigner's ECIES public key.
type CosignerECIESPubKey struct {
	ID        int
	PublicKey *ecies.PublicKey
}

// CosignerECIESKey is an ECIES key for an m-of-n threshold signer, composed of a private key and n public keys.
type CosignerECIESKey struct {
	ECIESKey  *ecies.PrivateKey  `json:"eciesKey"`
	ID        int                `json:"id"`
	ECIESPubs []*ecies.PublicKey `json:"eciesPubs"`
}

func (key *CosignerECIESKey) MarshalJSON() ([]byte, error) {
	type Alias CosignerECIESKey

	// marshal our private key and all public keys
	privateBytes := key.ECIESKey
	pubKeysBytes := make([][]byte, len(key.ECIESPubs))
	for i, pubKey := range key.ECIESPubs {
		pubKeysBytes[i] = pubKey.Bytes(true)
	}

	return json.Marshal(&struct {
		ECIESKey  []byte   `json:"eciesKey"`
		ECIESPubs [][]byte `json:"eciesPubs"`
		*Alias
	}{
		ECIESKey:  privateBytes.Bytes(),
		ECIESPubs: pubKeysBytes,
		Alias:     (*Alias)(key),
	})
}

func (key *CosignerECIESKey) UnmarshalJSON(data []byte) error {
	type Alias CosignerECIESKey

	aux := &struct {
		ECIESKey  []byte   `json:"eciesKey"`
		ECIESPubs [][]byte `json:"eciesPubs"`
		*Alias
	}{
		Alias: (*Alias)(key),
	}
	if err := json.Unmarshal(data, &aux); err != nil {
		return err
	}

	// unmarshal the public key bytes for each cosigner
	key.ECIESPubs = make([]*ecies.PublicKey, len(aux.ECIESPubs))
	for i, bytes := range aux.ECIESPubs {
		pub, err := ecies.NewPublicKeyFromBytes(bytes)
		if err != nil {
			return err
		}
		key.ECIESPubs[i] = pub
	}

	key.ECIESKey = ecies.NewPrivateKeyFromBytes(aux.ECIESKey)
	return nil
}

// LoadCosignerECIESKey loads a CosignerECIESKey from file.
func LoadCosignerECIESKey(file string) (CosignerECIESKey, error) {
	pvKey := CosignerECIESKey{}
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

// NewCosignerSecurityECIES creates a new CosignerSecurityECIES.
func NewCosignerSecurityECIES(key CosignerECIESKey, eciesPubKeys []CosignerECIESPubKey) *CosignerSecurityECIES {
	c := &CosignerSecurityECIES{
		key:          key,
		eciesPubKeys: make(map[int]CosignerECIESPubKey),
	}

	for _, pubKey := range eciesPubKeys {
		c.eciesPubKeys[pubKey.ID] = pubKey
	}

	return c
}

// GetID returns the ID of the cosigner.
func (c *CosignerSecurityECIES) GetID() int {
	return c.key.ID
}

// EncryptAndSign encrypts the nonce and signs it for authentication.
func (c *CosignerSecurityECIES) EncryptAndSign(id int, noncePub []byte, nonceShare []byte) (CosignerNonce, error) {
	nonce := CosignerNonce{
		SourceID: c.key.ID,
	}

	// grab the cosigner info for the ID being requested
	pubKey, ok := c.eciesPubKeys[id]
	if !ok {
		return nonce, fmt.Errorf("unknown cosigner ID: %d", id)
	}

	var encryptedPub []byte
	var encryptedShare []byte
	var eg errgroup.Group

	eg.Go(func() (err error) {
		encryptedShare, err = ecies.Encrypt(pubKey.PublicKey, nonceShare)
		return err
	})

	eg.Go(func() (err error) {
		encryptedPub, err = ecies.Encrypt(pubKey.PublicKey, noncePub)
		return err
	})

	if err := eg.Wait(); err != nil {
		return nonce, err
	}

	nonce.PubKey = encryptedPub
	nonce.Share = encryptedShare

	// sign the response payload with our private key
	// cosigners can verify the signature to confirm sender validity

	jsonBytes, err := cometjson.Marshal(nonce)

	if err != nil {
		return nonce, err
	}

	hash := sha256.Sum256(jsonBytes)
	signature, err := ecdsa.SignASN1(
		rand.Reader,
		&ecdsa.PrivateKey{
			PublicKey: ecdsa.PublicKey(*c.key.ECIESKey.PublicKey),
			D:         c.key.ECIESKey.D,
		},
		hash[:],
	)
	if err != nil {
		return nonce, err
	}

	nonce.DestinationID = id
	nonce.Signature = signature

	return nonce, nil
}

// DecryptAndVerify decrypts the nonce and verifies
// the signature to authenticate the source cosigner.
func (c *CosignerSecurityECIES) DecryptAndVerify(
	id int,
	encryptedNoncePub []byte,
	encryptedNonceShare []byte,
	signature []byte,
) ([]byte, []byte, error) {
	digestMsg := CosignerNonce{
		SourceID: id,
		PubKey:   encryptedNoncePub,
		Share:    encryptedNonceShare,
	}

	digestBytes, err := cometjson.Marshal(digestMsg)
	if err != nil {
		return nil, nil, err
	}

	digest := sha256.Sum256(digestBytes)
	pubKey, ok := c.eciesPubKeys[id]
	if !ok {
		return nil, nil, fmt.Errorf("unknown cosigner: %d", id)
	}

	validSignature := ecdsa.VerifyASN1((*ecdsa.PublicKey)(pubKey.PublicKey), digest[:], signature)
	if !validSignature {
		return nil, nil, fmt.Errorf("signature is invalid")
	}

	var eg errgroup.Group

	var noncePub []byte
	var nonceShare []byte

	eg.Go(func() (err error) {
		noncePub, err = ecies.Decrypt(c.key.ECIESKey, encryptedNoncePub)
		return err
	})

	eg.Go(func() (err error) {
		nonceShare, err = ecies.Decrypt(c.key.ECIESKey, encryptedNonceShare)
		return err
	})

	if err := eg.Wait(); err != nil {
		return nil, nil, err
	}

	return noncePub, nonceShare, nil
}
