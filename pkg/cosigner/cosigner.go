package cosigner

import (
	"time"

	"github.com/strangelove-ventures/horcrux/pkg/types"

	"github.com/strangelove-ventures/horcrux/pkg/proto"
)

type SignBlockResponse struct {
	Signature []byte
}

// SignRequest is sent to a co-signer to obtain their signature for the SignBytes
// The SignBytes should be a serialized block
type SignRequest struct {
	ChainID   string
	SignBytes []byte
}

type SignResponse struct {
	NoncePublic []byte
	Timestamp   time.Time
	Signature   []byte
}

// WrappedNonce is wrapping the Nonce to be used in communication between cosigners
type WrappedNonce struct {
	SourceID      int
	DestinationID int
	PubKey        []byte
	Share         []byte
	Signature     []byte
}

func (secretPart *WrappedNonce) toProto() *proto.Nonce {
	return &proto.Nonce{
		SourceID:      int32(secretPart.SourceID),
		DestinationID: int32(secretPart.DestinationID),
		PubKey:        secretPart.PubKey,
		Share:         secretPart.Share,
		Signature:     secretPart.Signature,
	}
}

// WrappedNonces is a list of WrappedNonce
type WrappedNonces []WrappedNonce

func (secretParts WrappedNonces) ToProto() (out []*proto.Nonce) {
	for _, secretPart := range secretParts {
		out = append(out, secretPart.toProto())
	}
	return
}

func NonceFromProto(secretPart *proto.Nonce) WrappedNonce {
	return WrappedNonce{
		SourceID:      int(secretPart.SourceID),
		DestinationID: int(secretPart.DestinationID),
		PubKey:        secretPart.PubKey,
		Share:         secretPart.Share,
		Signature:     secretPart.Signature,
	}
}

func NoncesFromProto(secretParts []*proto.Nonce) []WrappedNonce {
	out := make([]WrappedNonce, len(secretParts))
	for i, secretPart := range secretParts {
		out[i] = NonceFromProto(secretPart)
	}
	return out
}

type NoncesResponse struct {
	Nonces []WrappedNonce
}

type SetNoncesAndSignRequest struct {
	ChainID   string
	Nonces    []WrappedNonce
	HRST      types.HRSTKey
	SignBytes []byte
}
