package cosigner

import (
	"time"

	"github.com/strangelove-ventures/horcrux/src/types"

	"github.com/google/uuid"
	"github.com/strangelove-ventures/horcrux/proto/strangelove/proto"
	// "github.com/strangelove-ventures/horcrux/src/proto"
)

// SignatureRequest is sent to a co-signer to obtain their signature for the SignBytes
// The SignBytes should be a serialized block
type SignatureRequest struct {
	ChainID   string
	SignBytes []byte
	UUID      uuid.UUID
}

type SignatureResponse struct {
	NoncePublic []byte
	Timestamp   time.Time
	Signature   []byte
}

type Nonce struct {
	SourceID      int // Client ID
	DestinationID int // Server ID
	PubKey        []byte
	Share         []byte
	Signature     []byte
}

func (secretPart *Nonce) toProto() *proto.Nonce {
	return &proto.Nonce{
		SourceID:      int32(secretPart.SourceID),
		DestinationID: int32(secretPart.DestinationID),
		PubKey:        secretPart.PubKey,
		Share:         secretPart.Share,
		Signature:     secretPart.Signature,
	}
}

// Nonces is a list of CosignerNonce
type Nonces []Nonce

func (secretParts Nonces) toProto() (out []*proto.Nonce) {
	for _, secretPart := range secretParts {
		out = append(out, secretPart.toProto())
	}
	return
}

// FromProtoToNonce converts a proto.Nonce to a Nonce
func FromProtoToNonce(secretPart *proto.Nonce) Nonce {
	return Nonce{
		SourceID:      int(secretPart.SourceID),
		DestinationID: int(secretPart.DestinationID),
		PubKey:        secretPart.PubKey,
		Share:         secretPart.Share,
		Signature:     secretPart.Signature,
	}
}

func FromProtoToNonces(secretParts []*proto.Nonce) []Nonce {
	out := make([]Nonce, len(secretParts))
	for i, secretPart := range secretParts {
		out[i] = FromProtoToNonce(secretPart)
	}
	return out
}

type CosignerSignBlockRequest struct {
	ChainID string
	Block   *types.Block
}

type CosignerSignBlockResponse struct {
	Signature []byte
}

// CosignerUUIDNonces
type CosignerUUIDNonces struct {
	UUID   uuid.UUID // UUID is the unique identifier of the nonce
	Nonces Nonces
}

func (n *CosignerUUIDNonces) For(id int) *CosignerUUIDNonces {
	res := &CosignerUUIDNonces{UUID: n.UUID}
	for _, nonce := range n.Nonces {
		if nonce.DestinationID == id {
			res.Nonces = append(res.Nonces, nonce)
		}
	}
	return res
}

type CosignerUUIDNoncesMultiple []*CosignerUUIDNonces

func (n CosignerUUIDNoncesMultiple) ToProto() []*proto.UUIDNonce {
	out := make([]*proto.UUIDNonce, len(n))
	for i, nonces := range n {
		out[i] = &proto.UUIDNonce{
			Uuid:   nonces.UUID[:],
			Nonces: nonces.Nonces.toProto(),
		}
	}
	return out
}

type CosignerSetNoncesAndSignRequest struct {
	ChainID   string
	Nonces    *CosignerUUIDNonces
	HRST      types.HRST
	SignBytes []byte
}
