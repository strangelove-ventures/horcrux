package cosigner

/*
Package cosigner:
Cosinger is responsible for the network MPC communication between threshold signers.

You can think of it as:
- LocalCosigner is the server (we understand that local here is confussing but it is because it is local to the node)
- RemoteCosigner is the client
*/
import (
	"time"

	"github.com/strangelove-ventures/horcrux/pkg/types"

	"github.com/google/uuid"
	"github.com/strangelove-ventures/horcrux/signer/proto"
)

// threshold-ed25519
type MPC struct {
	// our own cosigner
	MyCosigner *LocalCosigner // TODO Should be an interface as well.

	// peer cosigners
	peerCosigners []*RemoteCosigner // "i.e clients to call"

}

type Localcosigner interface {
	// TODO - add methods
}
type Remotecosigner interface {
	// TODO - add methods
}

// CosignerSignRequest is sent to a co-signer to obtain their signature for the SignBytes
// The SignBytes should be a serialized block
type CosignerSignRequest struct {
	ChainID   string
	SignBytes []byte
	UUID      uuid.UUID
}

type CosignerSignResponse struct {
	NoncePublic []byte
	Timestamp   time.Time
	Signature   []byte
}

type CosignerNonce struct {
	SourceID      int
	DestinationID int
	PubKey        []byte
	Share         []byte
	Signature     []byte
}

func (secretPart *CosignerNonce) toProto() *proto.Nonce {
	return &proto.Nonce{
		SourceID:      int32(secretPart.SourceID),
		DestinationID: int32(secretPart.DestinationID),
		PubKey:        secretPart.PubKey,
		Share:         secretPart.Share,
		Signature:     secretPart.Signature,
	}
}

// CosignerNonces are a list of CosignerNonce
type CosignerNonces []CosignerNonce

func (secretParts CosignerNonces) toProto() (out []*proto.Nonce) {
	for _, secretPart := range secretParts {
		out = append(out, secretPart.toProto())
	}
	return
}

func CosignerNonceFromProto(secretPart *proto.Nonce) CosignerNonce {
	return CosignerNonce{
		SourceID:      int(secretPart.SourceID),
		DestinationID: int(secretPart.DestinationID),
		PubKey:        secretPart.PubKey,
		Share:         secretPart.Share,
		Signature:     secretPart.Signature,
	}
}

func CosignerNoncesFromProto(secretParts []*proto.Nonce) []CosignerNonce {
	out := make([]CosignerNonce, len(secretParts))
	for i, secretPart := range secretParts {
		out[i] = CosignerNonceFromProto(secretPart)
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
type CosignerUUIDNonces struct {
	UUID   uuid.UUID
	Nonces CosignerNonces
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
