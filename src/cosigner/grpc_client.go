package cosigner

import (
	"context"
	"net/url"
	"time"

	"github.com/google/uuid"
	"github.com/strangelove-ventures/horcrux/proto/strangelove/proto"

	// "github.com/strangelove-ventures/horcrux/src/proto"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

// var _ Cosigner = &RemoteCosigner{}

// CosignerClient uses CosignerGRPC to request signing from a remote cosigner
// Remote Cosigner are CLIENTS! to every other cosigner, including the the nodes local cosigner
// It calls the GRPC server of the other cosigner
// TODO: Change name to CosignerClient
type CosignerClient struct {
	id      int
	address string

	Client proto.CosignerClient // GRPC Client
}

// Placeholder function because of testing
// TODO: Change name to InitCosignerClient
func InitCosignerClient(id int, address string, client proto.CosignerClient) *CosignerClient {
	cosigner := &CosignerClient{
		id:      id,
		address: address, // address is the P2P URL of the remote cosigner
		Client:  client,
	}

	return cosigner
}

// NewCosignerClient returns a newly initialized RemoteCosigner
// TODO: Change name to NewCosignerClient
func NewCosignerClient(id int, address string) (*CosignerClient, error) {
	client, err := getGRPCClient(address) // address is the P2P URL of the cosigner server to dial
	if err != nil {
		return nil, err
	}
	cosigner := InitCosignerClient(id, address, client)
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
// TODO: Change name from ShamirIndex
func (cosigner *CosignerClient) GetIndex() int {
	return cosigner.id
}

// GetAddress returns the P2P URL of the remote cosigner
// Implements the cosigner interface
func (cosigner *CosignerClient) GetAddress() string {
	return cosigner.address
}

// GetPubKey returns public key of the validator.
// Implements Cosigner interface
// func (cosigner *RemoteCosigner) GetPubKey(_ string) (cometcrypto.PubKey, error) {
// 	return nil, fmt.Errorf("unexpected call to RemoteCosigner.GetPubKey")
// }

// VerifySignature validates a signed payload against the public key.
// Implements Cosigner interface
// func (cosigner *RemoteCosigner) VerifySignature(_ string, _, _ []byte) bool {
// 	return false
// }

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
func (cosigner *CosignerClient) GetNonces(
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
			Nonces: FromProtoToNonces(nonces.Nonces),
		}
	}
	return out, nil
}

// Implements the cosigner interface
func (cosigner *CosignerClient) SetNoncesAndSign(
	ctx context.Context,
	req CosignerSetNoncesAndSignRequest) (*SignatureResponse, error) {
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
	return &SignatureResponse{
		NoncePublic: res.GetNoncePublic(),
		Timestamp:   time.Unix(0, res.GetTimestamp()),
		Signature:   res.GetSignature(),
	}, nil
}

// TODO: This should move to ThresholdValidator. Its is not the responsibility of the cosigner
/*
func (cosigner *ClientCosigner) Sign(
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
*/
