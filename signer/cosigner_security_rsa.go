package signer

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"fmt"

	cometjson "github.com/cometbft/cometbft/libs/json"
	"golang.org/x/sync/errgroup"
)

var _ CosignerSecurity = &CosignerSecurityRSA{}

// CosignerSecurityRSA is an implementation of CosignerSecurity using RSA for encryption and P5S for digital signature.
type CosignerSecurityRSA struct {
	key        CosignerRSAKey
	rsaPubKeys map[int]CosignerRSAPubKey
}

// NewCosignerSecurityRSA creates a new CosignerSecurityRSA.
func NewCosignerSecurityRSA(key CosignerRSAKey, rsaPubKeys []CosignerRSAPubKey) *CosignerSecurityRSA {
	c := &CosignerSecurityRSA{
		key:        key,
		rsaPubKeys: make(map[int]CosignerRSAPubKey),
	}

	for _, pubKey := range rsaPubKeys {
		c.rsaPubKeys[pubKey.ID] = pubKey
	}

	return c
}

// GetID returns the ID of the cosigner.
func (c *CosignerSecurityRSA) GetID() int {
	return c.key.ID
}

// EncryptAndSign encrypts the nonce and signs it for authentication.
func (c *CosignerSecurityRSA) EncryptAndSign(id int, noncePub []byte, nonceShare []byte) (CosignerNonce, error) {
	nonce := CosignerNonce{
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

	nonce.SourcePubKey = encryptedPub
	nonce.EncryptedSharePart = encryptedShare

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
	nonce.SourceSig = signature

	return nonce, nil
}

// DecryptAndVerify decrypts the nonce and verifies the signature to authenticate the source cosigner.
func (c *CosignerSecurityRSA) DecryptAndVerify(id int, encryptedNoncePub []byte, encryptedNonceShare []byte, signature []byte) ([]byte, []byte, error) {
	digestMsg := CosignerNonce{
		SourceID:           id,
		SourcePubKey:       encryptedNoncePub,
		EncryptedSharePart: encryptedNonceShare,
	}

	digestBytes, err := cometjson.Marshal(digestMsg)
	if err != nil {
		return nil, nil, err
	}

	digest := sha256.Sum256(digestBytes)
	pubKey, ok := c.rsaPubKeys[id]
	if !ok {
		return nil, nil, fmt.Errorf("unknown cosigner: %d", id)
	}

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
