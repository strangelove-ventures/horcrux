package crypto

import "crypto/sha256"

type Address = []byte

func AddressHash(bz []byte) Address {
	hash := sha256.Sum256(bz)
	addr := hash[:20]
	return Address(addr)
}

type PrivKey interface {
	Bytes() []byte
	Sign(msg []byte) ([]byte, error)
	PubKey() PubKey
	Equals(PrivKey) bool
	Type() string
}

type PubKey interface {
	Address() Address
	Bytes() []byte
	VerifySignature(msg []byte, sig []byte) bool
	Equals(PubKey) bool
	Type() string
}
