package cosigner

/*
Package cosigner:
Cosinger is responsible for the network MPC communication between threshold signers.
The subdirectories are the different implementations of the MPC protocol.

You can think of it as:
- LocalCosigner is the server (we understand that local here is confussing but it is because it is local to the node)
- RemoteCosigner is the client
*/
import (
	"context"

	"github.com/google/uuid"
)

// MPC is the interface for the MPC protocol
// Its responsibility is to communicate with the other cosigners

type iCosigner interface {
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

type iHealth interface {
	Start(ctx context.Context) error
}
type iNonceCache interface {
	Start(ctx context.Context) error
}
type iNoncePruner interface {
	Start(ctx context.Context) error
}

/*
	type iServer interface {
		SetNoncesAndSign()
		// TODO - add methods
	}

	type iClient interface {
		SetNoncesAndSign()
		// TODO - add methods
	}
*/

type MPC struct {
	// logger log.Logger,
	chainID string

	// our own cosigner (i.e server)
	// MyCosigner *LocalCosigner // TODO Should be an interface as well.
	server iCosigner // TODO Should be an interface as well.

	// Cosigner peers (i.e the nodes clients to other servers)
	clients []iCosigner // "i.e clients to call" (map is slowr than slice but we need to be able to remove elements)

	serverHealth iHealth

	nonceCache  iNonceCache
	noncePruner iNoncePruner
}

// Takes a signature request from the validator and returns a signature response
func (mpc *MPC) SignBlock(ctx context.Context) error {
	return nil
}

func (mpc *MPC) Stop(ctx context.Context) error {
	return nil
}

func (mpc *MPC) Start(ctx context.Context) error {
	// mpc.logger.Info("Starting serverHealth services")
	go mpc.serverHealth.Start(ctx)

	// mpc.logger.Info("Starting serverHealth services")
	go mpc.nonceCache.Start(ctx)

	// mpc.logger.Info("Starting noncePruner services")
	go mpc.noncePruner.Start(ctx)

	// Should start the servers/clients?
	// TODO: Should we start the clients and servers here?

	return nil
}
