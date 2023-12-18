package bn254

import (
	"bytes"
	"crypto/sha256"
	"crypto/subtle"
	"fmt"
	"io"

	"github.com/cometbft/cometbft/crypto"
	"github.com/cometbft/cometbft/crypto/tmhash"
	cometjson "github.com/cometbft/cometbft/libs/json"
	ecdsa_bn254 "github.com/consensys/gnark-crypto/ecc/bn254/ecdsa"
)

//-------------------------------------

var (
	_ crypto.PrivKey = PrivKey{}
)

const (
	PrivKeyName = "tendermint/PrivKeyBn254"
	PubKeyName  = "tendermint/PubKeyBn254"
	// PubKeySize is is the size, in bytes, of public keys as used in this package.
	PubKeySize = 32
	// PrivateKeySize is the size, in bytes, of private keys as used in this package.
	PrivateKeySize = 64
	// Size of an Bn254 signature. Namely the size of a compressed
	// Bn254 point, and a field element. Both of which are 32 bytes.
	SignatureSize = 64
	// SeedSize is the size, in bytes, of private key seeds. These are the
	// private key representations used by RFC 8032.
	SeedSize = 32

	KeyType = "bn254"
)

func init() {
	cometjson.RegisterType(PubKey{}, PubKeyName)
	cometjson.RegisterType(PrivKey{}, PrivKeyName)
}

// PrivKey implements crypto.PrivKey.
type PrivKey []byte

// Bytes returns the privkey byte format.
func (privKey PrivKey) Bytes() []byte {
	return []byte(privKey)
}

// Sign produces a signature on the provided message.
// This assumes the privkey is wellformed in the golang format.
// The first 32 bytes should be random,
// corresponding to the normal bn254 private key.
// The latter 32 bytes should be the compressed public key.
// If these conditions aren't met, Sign will panic or produce an
// incorrect signature.
func (privKey PrivKey) Sign(msg []byte) ([]byte, error) {
	priv := new(ecdsa_bn254.PrivateKey)
	_, err := priv.SetBytes(privKey[:])
	if err != nil {
		return nil, err
	}

	hFunc := sha256.New()

	return priv.Sign(msg, hFunc)
}

// PubKey gets the corresponding public key from the private key.
//
// Panics if the private key is not initialized.
func (privKey PrivKey) PubKey() crypto.PubKey {
	// If the latter 32 bytes of the privkey are all zero, privkey is not
	// initialized.
	initialized := false
	for _, v := range privKey[32:] {
		if v != 0 {
			initialized = true
			break
		}
	}

	if !initialized {
		panic("Expected bn254 PrivKey to include concatenated pubkey bytes")
	}

	pubkeyBytes := make([]byte, PubKeySize)
	copy(pubkeyBytes, privKey[32:])
	return PubKey(pubkeyBytes)
}

// Equals - you probably don't need to use this.
// Runs in constant time based on length of the keys.
func (privKey PrivKey) Equals(other crypto.PrivKey) bool {
	if otherEd, ok := other.(PrivKey); ok {
		return subtle.ConstantTimeCompare(privKey[:], otherEd[:]) == 1
	}

	return false
}

func (privKey PrivKey) Type() string {
	return KeyType
}

// GenPrivKey generates a new bn254 private key.
// It uses OS randomness in conjunction with the current global random seed
// in cometbft/libs/rand to generate the private key.
func GenPrivKey() PrivKey {
	return genPrivKey(crypto.CReader())
}

// genPrivKey generates a new bn254 private key using the provided reader.
func genPrivKey(rand io.Reader) PrivKey {
	priv, err := ecdsa_bn254.GenerateKey(rand)
	if err != nil {
		panic(err)
	}

	return PrivKey(priv.Bytes())
}

//-------------------------------------

var _ crypto.PubKey = PubKey{}

// PubKey implements crypto.PubKey for the Bn254 signature scheme.
type PubKey []byte

// Address is the SHA256-20 of the raw pubkey bytes.
func (pubKey PubKey) Address() crypto.Address {
	if len(pubKey) != PubKeySize {
		panic("pubkey is incorrect size")
	}
	return crypto.Address(tmhash.SumTruncated(pubKey))
}

// Bytes returns the PubKey byte format.
func (pubKey PubKey) Bytes() []byte {
	return []byte(pubKey)
}

func (pubKey PubKey) VerifySignature(msg []byte, sig []byte) bool {
	// make sure we use the same algorithm to sign
	if len(sig) != SignatureSize {
		return false
	}

	pub := new(ecdsa_bn254.PublicKey)
	if _, err := pub.SetBytes(pubKey[:]); err != nil {
		return false
	}

	valid, _ := pub.Verify(msg, sig, sha256.New())
	return valid
}

func (pubKey PubKey) String() string {
	return fmt.Sprintf("PubKeyBn254{%X}", []byte(pubKey))
}

func (pubKey PubKey) Type() string {
	return KeyType
}

func (pubKey PubKey) Equals(other crypto.PubKey) bool {
	if otherEd, ok := other.(PubKey); ok {
		return bytes.Equal(pubKey[:], otherEd[:])
	}

	return false
}
