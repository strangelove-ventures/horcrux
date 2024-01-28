package node

import (
	"context"

	"github.com/google/uuid"

	"github.com/strangelove-ventures/horcrux/src/cosigner"
)

// Cosigner interface is a set of methods for an m-of-n threshold signature.
// This interface abstracts the underlying key storage and management
type iMPC interface {
	Pubkey()
	Sign()
	Start()
	Stop()
}

type ICosigner interface {
	// GetIndex gets the index of the cosigner
	// The index is the shamir index: 1, 2, etc...
	GetIndex() int

	// Get the P2P URL (GRPC)
	GetAddress() string

	// Get the combined public key
	// TODO: Change name to FetchPubKey
	// GetPubKey(chainID string) (cometcrypto.PubKey, error)

	// VerifySignature(chainID string, payload, signature []byte) bool

	// Get nonces for all cosigner shards
	GetNonces(ctx context.Context, uuids []uuid.UUID) (cosigner.CosignerUUIDNoncesMultiple, error)

	// Sign the requested bytes
	SetNoncesAndSign(ctx context.Context, req cosigner.CosignerSetNoncesAndSignRequest) (*cosigner.SignatureResponse, error)
}

// TODO: Move to MPC package
type ICosigners []ICosigner // ICosigners is a list of ICosigner's
func (cosigners ICosigners) GetByIndex(id int) ICosigner {
	// TODO: Add error handling
	for _, cosigner := range cosigners {
		if cosigner.GetIndex() == id {
			return cosigner
		}
	}
	return nil
}
