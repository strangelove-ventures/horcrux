package cosigner

import "github.com/strangelove-ventures/horcrux/src/types"

// Interface for the local cosigner whether it's a soft sign or HSM
// The ThresholdSigner interface is used to sign messages with a threshold signature.
type IThresholdSigner interface {
	// GetPubKey returns the public key bytes for the combination of all cosigners.
	GetPubKey() []byte

	// Sign signs a byte payload with the provided nonces.
	Sign(nonces []types.Nonce, payload []byte) ([]byte, error)

	// CombineSignatures combines multiple partial signatures to a full signature.
	CombineSignatures([]types.PartialSignature) ([]byte, error)
}

type IThresholdDealer interface {
	GenerateNonces(threshold, total uint8) (types.Nonces, error)
}

type IThreshold interface {
	IThresholdSigner
	IThresholdDealer
}
