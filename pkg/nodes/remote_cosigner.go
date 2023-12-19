package nodes

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

	Client proto.CosignerClient
}

// Placeholder function because of testing
func InitRemoteCosigner(id int, address string, client proto.CosignerClient) *RemoteCosigner {
	cosigner := &RemoteCosigner{
		id:      id,
		address: address,
		Client:  client,
	}

	return cosigner
}

// NewRemoteCosigner returns a newly initialized RemoteCosigner
func NewRemoteCosigner(id int, address string) (*RemoteCosigner, error) {
	client, err := getGRPCClient(address)
	if err != nil {
		return nil, err
	}
	cosigner := InitRemoteCosigner(id, address, client)
	return cosigner, nil
	/*
		cosigner := &RemoteCosigner{
			id:      id,
			address: address,
			Client:  client,
		}

		return cosigner, nil
	*/
}

// GetID returns the Index of the remote cosigner
// Implements the cosigner interface
func (cosigner *RemoteCosigner) GetIndex() int {
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

func getGRPCClient(address string) (proto.CosignerClient, error) {
	var grpcAddress string
	url, err := url.Parse(address)
	if err != nil {
		grpcAddress = address
	} else {
		grpcAddress = url.Host
	}
	conn, err := grpc.Dial(grpcAddress, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		return nil, err
	}
	return proto.NewCosignerClient(conn), nil
}

// GetNonces implements the cosigner interface
func (cosigner *RemoteCosigner) GetNonces(
	ctx context.Context,
	uuids []uuid.UUID,
) (CosignerUUIDNoncesMultiple, error) {
	us := make([][]byte, len(uuids))
	for i, u := range uuids {
		us[i] = make([]byte, 16)
		copy(us[i], u[:])
	}
	res, err := cosigner.Client.GetNonces(ctx, &proto.GetNoncesRequest{
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
	res, err := cosigner.Client.SetNoncesAndSign(ctx, &proto.SetNoncesAndSignRequest{
		Uuid:      req.Nonces.UUID[:],
		ChainID:   req.ChainID,
		Nonces:    req.Nonces.Nonces.toProto(),
		Hrst:      req.HRST.ToProto(),
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

func (cosigner *RemoteCosigner) Sign(
	ctx context.Context,
	req CosignerSignBlockRequest,
) (*CosignerSignBlockResponse, error) {
	res, err := cosigner.Client.SignBlock(ctx, &proto.SignBlockRequest{
		ChainID: req.ChainID,
		Block:   req.Block.ToProto(),
	})
	if err != nil {
		return nil, err
	}
	return &CosignerSignBlockResponse{
		Signature: res.GetSignature(),
	}, nil
}
