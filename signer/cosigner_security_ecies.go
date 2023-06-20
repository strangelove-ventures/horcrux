package signer

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"fmt"

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

	nonce.SourcePubKey = encryptedPub
	nonce.EncryptedSharePart = encryptedShare

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
	nonce.SourceSig = signature

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
		SourceID:           id,
		SourcePubKey:       encryptedNoncePub,
		EncryptedSharePart: encryptedNonceShare,
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
