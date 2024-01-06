package nodesecurity

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"os"

	cometjson "github.com/cometbft/cometbft/libs/json"
	"github.com/strangelove-ventures/horcrux/src/cosigner"
	"golang.org/x/sync/errgroup"
)

var _ cosigner.ICosignerSecurity = &CosignerSecurityRSA{}

// CosignerSecurityRSA is an implementation of CosignerSecurity using RSA for encryption and P5S for digital signature.
type CosignerSecurityRSA struct {
	key        CosignerRSAKey
	rsaPubKeys map[int]CosignerRSAPubKey
}

// CosignerRSAPubKey is a cosigner's RSA public key.
type CosignerRSAPubKey struct {
	ID        int
	PublicKey rsa.PublicKey
}

// CosignerRSAKey is an RSA key for an m-of-n threshold signer, composed of a private key and n public keys.
type CosignerRSAKey struct {
	RSAKey  rsa.PrivateKey   `json:"rsaKey"`
	ID      int              `json:"id"`
	RSAPubs []*rsa.PublicKey `json:"rsaPubs"`
}

func (key *CosignerRSAKey) MarshalJSON() ([]byte, error) {
	type Alias CosignerRSAKey

	// marshal our private key and all public keys
	privateBytes := x509.MarshalPKCS1PrivateKey(&key.RSAKey)
	rsaPubKeysBytes := make([][]byte, len(key.RSAPubs))
	for i, pubKey := range key.RSAPubs {
		publicBytes := x509.MarshalPKCS1PublicKey(pubKey)
		rsaPubKeysBytes[i] = publicBytes
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
	key.RSAPubs = make([]*rsa.PublicKey, len(aux.RSAPubs))
	for i, bytes := range aux.RSAPubs {
		cosignerRsaPubkey, err := x509.ParsePKCS1PublicKey(bytes)
		if err != nil {
			return err
		}
		key.RSAPubs[i] = cosignerRsaPubkey
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

// NewCosignerSecurityRSA creates a new CosignerSecurityRSA.
func NewCosignerSecurityRSA(key CosignerRSAKey) *CosignerSecurityRSA {
	c := &CosignerSecurityRSA{
		key:        key,
		rsaPubKeys: make(map[int]CosignerRSAPubKey),
	}

	for i, pubKey := range key.RSAPubs {
		c.rsaPubKeys[i+1] = CosignerRSAPubKey{
			ID:        i + 1,
			PublicKey: *pubKey,
		}
	}

	return c
}

// GetID returns the Index of the cosigner.
func (c *CosignerSecurityRSA) GetID() int {
	return c.key.ID
}

// EncryptAndSign encrypts the nonce and signs it for authentication.
func (c *CosignerSecurityRSA) EncryptAndSign(id int, noncePub []byte, nonceShare []byte) (cosigner.Nonce, error) {
	nonce := cosigner.Nonce{
		SourceID: c.key.ID,
	}

	// grab the cosigner info for the Index being requested
	pubKey, ok := c.rsaPubKeys[id]
	if !ok {
		return nonce, fmt.Errorf("unknown cosigner Index: %d", id)
	}

	var encryptedPub []byte
	var encryptedShare []byte
	var eg errgroup.Group

	eg.Go(func() (err error) {
		encryptedShare, err = rsa.EncryptOAEP(sha256.New(), rand.Reader, &pubKey.PublicKey, nonceShare, nil)
		return err
	})

	eg.Go(func() (err error) {
		encryptedPub, err = rsa.EncryptOAEP(sha256.New(), rand.Reader, &pubKey.PublicKey, noncePub, nil)
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
	signature, err := rsa.SignPSS(rand.Reader, &c.key.RSAKey, crypto.SHA256, hash[:], nil)
	if err != nil {
		return nonce, err
	}

	nonce.DestinationID = id
	nonce.Signature = signature

	return nonce, nil
}

// DecryptAndVerify decrypts the nonce and verifies
// the signature to authenticate the source cosigner.
func (c *CosignerSecurityRSA) DecryptAndVerify(
	id int,
	encryptedNoncePub []byte,
	encryptedNonceShare []byte,
	signature []byte,
) ([]byte, []byte, error) {
	pubKey, ok := c.rsaPubKeys[id]
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

	err = rsa.VerifyPSS(&pubKey.PublicKey, crypto.SHA256, digest[:], signature, nil)
	if err != nil {
		return nil, nil, err
	}

	var eg errgroup.Group

	var noncePub []byte
	var nonceShare []byte

	eg.Go(func() (err error) {
		noncePub, err = rsa.DecryptOAEP(sha256.New(), rand.Reader, &c.key.RSAKey, encryptedNoncePub, nil)
		return err
	})

	eg.Go(func() (err error) {
		nonceShare, err = rsa.DecryptOAEP(sha256.New(), rand.Reader, &c.key.RSAKey, encryptedNonceShare, nil)
		return err
	})

	if err := eg.Wait(); err != nil {
		return nil, nil, err
	}

	return noncePub, nonceShare, nil
}
