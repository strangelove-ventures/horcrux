package cosigner

/*
Package cosigner:
Cosinger is responsible for the network MPC communication between threshold signers.

You can think of it as:
- LocalCosigner is the server (we understand that local here is confussing but it is because it is local to the node)
- RemoteCosigner is the client
*/
import (
	"context"
	"time"

	"github.com/strangelove-ventures/horcrux/pkg/types"

	"github.com/google/uuid"
	"github.com/strangelove-ventures/horcrux/signer/proto"
)

// MPC is the interface for the MPC protocol
// Its responsibility is to communicate with the other cosigners

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
	GetNonces(ctx context.Context, uuids []uuid.UUID) (CosignerUUIDNoncesMultiple, error)

	// Sign the requested bytes
	SetNoncesAndSign(ctx context.Context, req CosignerSetNoncesAndSignRequest) (*SignatureResponse, error)
}

type iMPC interface {
	Pubkey()
	Sign()
	Start()
	Stop()
}

type MPC struct {
	// logger log.Logger,
	chainID string
	// our own cosigner (i.e server)
	// MyCosigner *LocalCosigner // TODO Should be an interface as well.
	server iServer // TODO Should be an interface as well.

	// peer cosigners (i.e clients to call)
	clients map[string]iClient // "i.e clients to call"

	serverHealth iHealth

	nonceCache  iNonceCache
	noncePruner iNoncePruner
}

func (mpc *MPC) Start(ctx context.Context) error {
	//mpc.logger.Info("Starting ThresholdValidator services")

	go mpc.serverHealth.Start(ctx)

	go mpc.nonceCache.Start(ctx)

	go mpc.noncePruner.Start(ctx)

	return nil
}

type iHealth interface {
	Start(ctx context.Context) error
}
type iNonceCache interface {
	Start(ctx context.Context) error
}
type iNoncePruner interface {
	Start(ctx context.Context) error
}

type iServer interface {
	// TODO - add methods
}
type iClient interface {
	// TODO - add methods
}

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
