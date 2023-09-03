package cosigner

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
	"golang.org/x/sync/errgroup"
)

var _ ICosignerSecurity = &SecurityRSA{}

// SecurityRSA is an implementation of CosignerSecurity using RSA for encryption and P5S for digital signature.
type SecurityRSA struct {
	key        CosignRSAKey
	rsaPubKeys map[int]CosignRSAPubKey
}

// CosignRSAKey is a cosigner's RSA public key.
type CosignRSAPubKey struct {
	ID        int
	PublicKey rsa.PublicKey
}

// CosignRSAKey is an RSA key for an m-of-n threshold signer, composed of a private key and n public keys.
type CosignRSAKey struct {
	RSAKey  rsa.PrivateKey   `json:"rsaKey"`
	ID      int              `json:"id"`
	RSAPubs []*rsa.PublicKey `json:"rsaPubs"`
}

func (key *CosignRSAKey) MarshalJSON() ([]byte, error) {
	type Alias CosignRSAKey

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

func (key *CosignRSAKey) UnmarshalJSON(data []byte) error {
	type Alias CosignRSAKey

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

// LoadCosignRSAKey loads a CosignRSAKey from file.
func LoadCosignRSAKey(file string) (CosignRSAKey, error) {
	pvKey := CosignRSAKey{}
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
func NewCosignerSecurityRSA(key CosignRSAKey) *SecurityRSA {
	c := &SecurityRSA{
		key:        key,
		rsaPubKeys: make(map[int]CosignRSAPubKey),
	}

	for i, pubKey := range key.RSAPubs {
		c.rsaPubKeys[i+1] = CosignRSAPubKey{
			ID:        i + 1,
			PublicKey: *pubKey,
		}
	}

	return c
}

// GetID returns the ID of the cosigner.
func (c *SecurityRSA) GetID() int {
	return c.key.ID
}

// EncryptAndSign encrypts the nonce and signs it for authentication.
func (c *SecurityRSA) EncryptAndSign(id int, noncePub []byte, nonceShare []byte) (CosignNonce, error) {
	nonce := CosignNonce{
		SourceID: c.key.ID,
	}

	// grab the cosigner info for the ID being requested
	pubKey, ok := c.rsaPubKeys[id]
	if !ok {
		return nonce, fmt.Errorf("unknown cosigner ID: %d", id)
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
func (c *SecurityRSA) DecryptAndVerify(
	id int,
	encryptedNoncePub []byte,
	encryptedNonceShare []byte,
	signature []byte,
) ([]byte, []byte, error) {
	pubKey, ok := c.rsaPubKeys[id]
	if !ok {
		return nil, nil, fmt.Errorf("unknown cosigner: %d", id)
	}

	digestMsg := CosignNonce{
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
