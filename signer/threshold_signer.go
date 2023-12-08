package signer

import (
	"github.com/strangelove-ventures/horcrux/pkg/types"
)

// Interface for the local signer whether it's a soft sign or HSM
type ThresholdSigner interface {
	// PubKey returns the public key bytes for the combination of all cosigners.
	PubKey() []byte

	// Sign signs a byte payload with the provided nonces.
	Sign(nonces []types.Nonce, payload []byte) ([]byte, error)

	// CombineSignatures combines multiple partial signatures to a full signature.
	CombineSignatures([]types.PartialSignature) ([]byte, error)
}
