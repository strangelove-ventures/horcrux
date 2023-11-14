package signer

import (
	"context"
	"fmt"
	"net/url"
	"time"

	cometcrypto "github.com/cometbft/cometbft/crypto"
	"github.com/google/uuid"
	"github.com/strangelove-ventures/horcrux/signer/proto"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

var _ Cosigner = &RemoteCosigner{}

// RemoteCosigner uses CosignerGRPC to request signing from a remote cosigner
type RemoteCosigner struct {
	id      int
	address string
}

// NewRemoteCosigner returns a newly initialized RemoteCosigner
func NewRemoteCosigner(id int, address string) *RemoteCosigner {

	cosigner := &RemoteCosigner{
		id:      id,
		address: address,
	}
	return cosigner
}

const (
	rpcTimeout = 4 * time.Second
)

func getContext() (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.Background(), rpcTimeout)
}

// GetID returns the ID of the remote cosigner
// Implements the cosigner interface
func (cosigner *RemoteCosigner) GetID() int {
	return cosigner.id
}

// GetAddress returns the P2P URL of the remote cosigner
// Implements the cosigner interface
func (cosigner *RemoteCosigner) GetAddress() string {
	return cosigner.address
}

// GetPubKey returns public key of the validator.
// Implements Cosigner interface
func (cosigner *RemoteCosigner) GetPubKey(_ string) (cometcrypto.PubKey, error) {
	return nil, fmt.Errorf("unexpected call to RemoteCosigner.GetPubKey")
}

// VerifySignature validates a signed payload against the public key.
// Implements Cosigner interface
func (cosigner *RemoteCosigner) VerifySignature(_ string, _, _ []byte) bool {
	return false
}

func (cosigner *RemoteCosigner) getGRPCClient() (proto.CosignerClient, *grpc.ClientConn, error) {
	var grpcAddress string
	url, err := url.Parse(cosigner.address)
	if err != nil {
		grpcAddress = cosigner.address
	} else {
		grpcAddress = url.Host
	}
	conn, err := grpc.Dial(grpcAddress, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		return nil, nil, err
	}
	return proto.NewCosignerClient(conn), conn, nil
}

// Implements the cosigner interface
func (cosigner *RemoteCosigner) GetNonces(
	ctx context.Context,
	uuids []uuid.UUID,
) (CosignerUUIDNoncesMultiple, error) {
	client, conn, err := cosigner.getGRPCClient()
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	us := make([][]byte, len(uuids))
	for i, u := range uuids {
		us[i] = make([]byte, 16)
		copy(us[i], u[:])
	}
	res, err := client.GetNonces(ctx, &proto.GetNoncesRequest{
		Uuids: us,
	})
	if err != nil {
		return nil, err
	}
	out := make(CosignerUUIDNoncesMultiple, len(res.Nonces))
	for i, nonces := range res.Nonces {
		out[i] = &CosignerUUIDNonces{
			UUID:   uuid.UUID(nonces.Uuid),
			Nonces: CosignerNoncesFromProto(nonces.Nonces),
		}
	}
	return out, nil
}

// Implements the cosigner interface
func (cosigner *RemoteCosigner) SetNoncesAndSign(
	ctx context.Context,
	req CosignerSetNoncesAndSignRequest) (*CosignerSignResponse, error) {
	client, conn, err := cosigner.getGRPCClient()
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	res, err := client.SetNoncesAndSign(ctx, &proto.SetNoncesAndSignRequest{
		Uuid:      req.Nonces.UUID[:],
		ChainID:   req.ChainID,
		Nonces:    CosignerNonces(req.Nonces.Nonces).toProto(),
		Hrst:      req.HRST.toProto(),
		SignBytes: req.SignBytes,
	})
	if err != nil {
		return nil, err
	}
	return &CosignerSignResponse{
		NoncePublic: res.GetNoncePublic(),
		Timestamp:   time.Unix(0, res.GetTimestamp()),
		Signature:   res.GetSignature(),
	}, nil
}
