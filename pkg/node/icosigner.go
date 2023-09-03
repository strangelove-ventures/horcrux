package node

import (
	cometcrypto "github.com/cometbft/cometbft/crypto"
	"github.com/strangelove-ventures/horcrux/pkg/cosigner"
	"github.com/strangelove-ventures/horcrux/pkg/types"
)

// ICosigner interface is a set of methods for an m-of-n threshold signature.
// This interface abstracts the underlying key storage and management
type ICosigner interface {
	// GetID should return the id number of the cosigner
	// The ID is the shamir index: 1, 2, etc...
	GetID() int

	// GetAddress gets the P2P URL (GRPC and Raft)
	GetAddress() string

	// GetPubKey gets the combined public key (permament)
	// Not used by Remote Cosigner
	GetPubKey(chainID string) (cometcrypto.PubKey, error)

	VerifySignature(chainID string, payload, signature []byte) bool

	// GetNonces requests nonce frpm the peer cosigners
	GetNonces(chainID string, hrst types.HRSTKey) (*cosigner.NoncesResponse, error)

	// Sign the requested bytes
	SetNoncesAndSign(req cosigner.SetNoncesAndSignRequest) (*cosigner.SignResponse, error)
}
