package signer

import (
	"context"
	"fmt"
	"net/url"
	"time"

	cometcrypto "github.com/cometbft/cometbft/crypto"
	"github.com/google/uuid"
	"github.com/strangelove-ventures/horcrux/v3/signer/proto"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

var _ Cosigner = &RemoteCosigner{}

// RemoteCosigner uses CosignerGRPC to request signing from a remote cosigner
type RemoteCosigner struct {
	id      int
	address string

	client proto.CosignerClient
}

// NewRemoteCosigner returns a newly initialized RemoteCosigner
func NewRemoteCosigner(id int, address string) (*RemoteCosigner, error) {
	client, err := getGRPCClient(address)
	if err != nil {
		return nil, err
	}

	cosigner := &RemoteCosigner{
		id:      id,
		address: address,
		client:  client,
	}

	return cosigner, nil
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

// Implements the cosigner interface
func (cosigner *RemoteCosigner) GetNonces(
	ctx context.Context,
	uuids []uuid.UUID,
) (CosignerUUIDNoncesMultiple, error) {
	us := make([][]byte, len(uuids))
	for i, u := range uuids {
		us[i] = make([]byte, 16)
		copy(us[i], u[:])
	}
	res, err := cosigner.client.GetNonces(ctx, &proto.GetNoncesRequest{
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
	cosignerReq := &proto.SetNoncesAndSignRequest{
		Uuid:      req.Nonces.UUID[:],
		ChainID:   req.ChainID,
		Nonces:    req.Nonces.Nonces.toProto(),
		Hrst:      req.HRST.toProto(),
		SignBytes: req.SignBytes,
	}

	if req.VoteExtensionNonces != nil && len(req.VoteExtensionSignBytes) > 0 {
		cosignerReq.VoteExtUuid = req.VoteExtensionNonces.UUID[:]
		cosignerReq.VoteExtNonces = req.VoteExtensionNonces.Nonces.toProto()
		cosignerReq.VoteExtSignBytes = req.VoteExtensionSignBytes
	}

	res, err := cosigner.client.SetNoncesAndSign(ctx, cosignerReq)
	if err != nil {
		return nil, err
	}
	return &CosignerSignResponse{
		NoncePublic:              res.NoncePublic,
		Timestamp:                time.Unix(0, res.Timestamp),
		Signature:                res.Signature,
		VoteExtensionSignature:   res.VoteExtSignature,
		VoteExtensionNoncePublic: res.VoteExtNoncePublic,
	}, nil
}

func (cosigner *RemoteCosigner) Sign(
	ctx context.Context,
	req CosignerSignBlockRequest,
) (*CosignerSignBlockResponse, error) {
	res, err := cosigner.client.SignBlock(ctx, &proto.SignBlockRequest{
		ChainID: req.ChainID,
		Block:   req.Block.ToProto(),
	})
	if err != nil {
		return nil, err
	}
	return &CosignerSignBlockResponse{
		Signature:              res.Signature,
		VoteExtensionSignature: res.VoteExtSignature,
	}, nil
}
