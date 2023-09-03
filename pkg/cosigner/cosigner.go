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

type CosignNonce struct {
	SourceID      int
	DestinationID int
	PubKey        []byte
	Share         []byte
	Signature     []byte
}

func (secretPart *CosignNonce) toProto() *proto.Nonce {
	return &proto.Nonce{
		SourceID:      int32(secretPart.SourceID),
		DestinationID: int32(secretPart.DestinationID),
		PubKey:        secretPart.PubKey,
		Share:         secretPart.Share,
		Signature:     secretPart.Signature,
	}
}

// CosignNonces is a list of CosignNonce
type CosignNonces []CosignNonce

func (secretParts CosignNonces) ToProto() (out []*proto.Nonce) {
	for _, secretPart := range secretParts {
		out = append(out, secretPart.toProto())
	}
	return
}

func CosignNonceFromProto(secretPart *proto.Nonce) CosignNonce {
	return CosignNonce{
		SourceID:      int(secretPart.SourceID),
		DestinationID: int(secretPart.DestinationID),
		PubKey:        secretPart.PubKey,
		Share:         secretPart.Share,
		Signature:     secretPart.Signature,
	}
}

func CosignNoncesFromProto(secretParts []*proto.Nonce) []CosignNonce {
	out := make([]CosignNonce, len(secretParts))
	for i, secretPart := range secretParts {
		out[i] = CosignNonceFromProto(secretPart)
	}
	return out
}

type SetNonceRequest struct {
	ChainID   string
	SourceID  int
	PubKey    []byte
	Share     []byte
	Signature []byte
	Height    int64
	Round     int64
	Step      int8
	Timestamp time.Time
}

type NoncesResponse struct {
	Nonces []CosignNonce
}

type SetNoncesAndSignRequest struct {
	ChainID   string
	Nonces    []CosignNonce
	HRST      types.HRSTKey
	SignBytes []byte
}
