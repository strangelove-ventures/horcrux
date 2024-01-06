package nodesecurity

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"math/big"
	"os"

	cometjson "github.com/cometbft/cometbft/libs/json"
	"github.com/ethereum/go-ethereum/crypto/ecies"
	"github.com/ethereum/go-ethereum/crypto/secp256k1"
	"github.com/strangelove-ventures/horcrux/src/cosigner"
	"golang.org/x/sync/errgroup"
)

var _ cosigner.ICosignerSecurity = &CosignerSecurityECIES{}

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
	privateBytes := key.ECIESKey.D.Bytes()
	pubKeysBytes := make([][]byte, len(key.ECIESPubs))
	for i, pubKey := range key.ECIESPubs {
		pubBz := make([]byte, 65)
		pubBz[0] = 0x04
		copy(pubBz[1:33], pubKey.X.Bytes())
		copy(pubBz[33:65], pubKey.Y.Bytes())
		pubKeysBytes[i] = pubBz
	}

	return json.Marshal(&struct {
		ECIESKey  []byte   `json:"eciesKey"`
		ECIESPubs [][]byte `json:"eciesPubs"`
		*Alias
	}{
		ECIESKey:  privateBytes,
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
		pub := &ecies.PublicKey{
			X:      new(big.Int).SetBytes(bytes[1:33]),
			Y:      new(big.Int).SetBytes(bytes[33:]),
			Curve:  secp256k1.S256(),
			Params: ecies.ECIES_AES128_SHA256,
		}

		key.ECIESPubs[i] = pub
	}

	key.ECIESKey = &ecies.PrivateKey{
		PublicKey: *key.ECIESPubs[aux.ID-1],
		D:         new(big.Int).SetBytes(aux.ECIESKey),
	}

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
func NewCosignerSecurityECIES(key CosignerECIESKey) *CosignerSecurityECIES {
	c := &CosignerSecurityECIES{
		key:          key,
		eciesPubKeys: make(map[int]CosignerECIESPubKey, len(key.ECIESPubs)),
	}

	for i, pubKey := range key.ECIESPubs {
		c.eciesPubKeys[i+1] = CosignerECIESPubKey{
			ID:        i + 1,
			PublicKey: pubKey,
		}
	}

	return c
}

// GetID returns the Index of the cosigner.
func (c *CosignerSecurityECIES) GetID() int {
	return c.key.ID
}

// EncryptAndSign encrypts the nonce and signs it for authentication.
func (c *CosignerSecurityECIES) EncryptAndSign(
	id int, noncePub []byte, nonceShare []byte) (cosigner.Nonce, error) {
	nonce := cosigner.Nonce{
		SourceID: c.key.ID,
	}

	// grab the cosigner info for the Index being requested
	pubKey, ok := c.eciesPubKeys[id]
	if !ok {
		return nonce, fmt.Errorf("unknown cosigner Index: %d", id)
	}

	var encryptedPub []byte
	var encryptedShare []byte
	var eg errgroup.Group

	eg.Go(func() (err error) {
		encryptedShare, err = ecies.Encrypt(rand.Reader, pubKey.PublicKey, nonceShare, nil, nil)
		return err
	})

	eg.Go(func() (err error) {
		encryptedPub, err = ecies.Encrypt(rand.Reader, pubKey.PublicKey, noncePub, nil, nil)
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
		c.key.ECIESKey.ExportECDSA(),
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
	pubKey, ok := c.eciesPubKeys[id]
	if !ok {
		return nil, nil, fmt.Errorf("unknown cosigner: %d", id)
	}

	digestMsg := cosigner.Nonce{
		SourceID: id,
		PubKey:   encryptedNoncePub,
		Share:    encryptedNonceShare,
	}

	digestBytes, err := cometjson.Marshal(digestMsg)
	if err != nil {
		return nil, nil, err
	}

	digest := sha256.Sum256(digestBytes)

	validSignature := ecdsa.VerifyASN1(pubKey.PublicKey.ExportECDSA(), digest[:], signature)
	if !validSignature {
		return nil, nil, fmt.Errorf("signature is invalid")
	}

	var eg errgroup.Group

	var noncePub []byte
	var nonceShare []byte

	eg.Go(func() (err error) {
		noncePub, err = c.key.ECIESKey.Decrypt(encryptedNoncePub, nil, nil)
		if err != nil {
			return fmt.Errorf("failed to decrypt nonce pub: %w", err)
		}
		return nil
	})

	eg.Go(func() (err error) {
		nonceShare, err = c.key.ECIESKey.Decrypt(encryptedNonceShare, nil, nil)
		if err != nil {
			return fmt.Errorf("failed to decrypt nonce share: %w", err)
		}
		return nil
	})

	if err := eg.Wait(); err != nil {
		return nil, nil, err
	}

	return noncePub, nonceShare, nil
}
