package signer

import (
	"context"
	"net/url"
	"time"

	proto "github.com/strangelove-ventures/horcrux/signer/proto"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

// RemoteCosigner uses tendermint rpc to request signing from a remote cosigner
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

func (cosigner *RemoteCosigner) getGRPCClient() (proto.CosignerGRPCClient, *grpc.ClientConn, error) {
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
	return proto.NewCosignerGRPCClient(conn), conn, nil
}

// Implements the cosigner interface
func (cosigner *RemoteCosigner) GetEphemeralSecretParts(
	req HRSTKey) (*CosignerEphemeralSecretPartsResponse, error) {
	client, conn, err := cosigner.getGRPCClient()
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	context, cancelFunc := getContext()
	defer cancelFunc()
	res, err := client.GetEphemeralSecretParts(context, &proto.CosignerGRPCGetEphemeralSecretPartsRequest{
		Hrst: req.toProto(),
	})
	if err != nil {
		return nil, err
	}
	return &CosignerEphemeralSecretPartsResponse{
		EncryptedSecrets: CosignerEphemeralSecretPartsFromProto(res.GetEncryptedSecrets()),
	}, nil
}

// Implements the cosigner interface
func (cosigner *RemoteCosigner) SetEphemeralSecretPartsAndSign(
	req CosignerSetEphemeralSecretPartsAndSignRequest) (*CosignerSignResponse, error) {
	client, conn, err := cosigner.getGRPCClient()
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	context, cancelFunc := getContext()
	defer cancelFunc()
	res, err := client.SetEphemeralSecretPartsAndSign(context, &proto.CosignerGRPCSetEphemeralSecretPartsAndSignRequest{
		EncryptedSecrets: CosignerEphemeralSecretParts(req.EncryptedSecrets).toProto(),
		Hrst:             req.HRST.toProto(),
		SignBytes:        req.SignBytes,
	})
	if err != nil {
		return nil, err
	}
	return &CosignerSignResponse{
		EphemeralPublic: res.GetEphemeralPublic(),
		Timestamp:       time.Unix(0, res.GetTimestamp()),
		Signature:       res.GetSignature(),
	}, nil
}
