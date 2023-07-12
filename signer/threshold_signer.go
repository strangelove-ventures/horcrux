package signer

// Interface for the local signer whether it's a soft sign or HSM
type ThresholdSigner interface {
	// PubKey returns the public key bytes for the combination of all cosigners.
	PubKey() []byte

	// GenerateNonces deals nonces for all cosigners.
	GenerateNonces() (Nonces, error)

	// Sign signs a byte payload with the provided nonces.
	Sign(nonces []Nonce, payload []byte) ([]byte, error)

	// CombineSignatures combines multiple partial signatures to a full signature.
	CombineSignatures([]PartialSignature) ([]byte, error)
}

// Nonces contains the ephemeral information generated by one cosigner for all other cosigners.
type Nonces struct {
	PubKey []byte
	Shares [][]byte
}

// Nonce is the ephemeral information from another cosigner destined for this cosigner.
type Nonce struct {
	ID     int
	Share  []byte
	PubKey []byte
}

// PartialSignature contains the signature and identifier for a piece of the combined signature.
type PartialSignature struct {
	ID        int
	Signature []byte
}
