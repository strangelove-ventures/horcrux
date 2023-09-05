package cosigner

// RemoteCosigner is a Cosigner implementation that uses gRPC make to request from other Cosigners
import (
	"context"
	"fmt"
	"net/url"
	"time"

	"github.com/strangelove-ventures/horcrux/pkg/types"

	cometcrypto "github.com/cometbft/cometbft/crypto"
	"github.com/strangelove-ventures/horcrux/pkg/proto"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

// RemoteCosigner uses CosignerGRPC to request/query a signing process from a LocalCosigner
//
//   - RemoteCosigner acts as a client(!) and requests via gRPC the other
//     "node's" LocalCosigner to set the nonces and sign the payload and respons.
//   - RemoteCosigner --> gRPC --> LocalCosigner
//   - RemoteCosigner implements the Cosigner interface
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

func GetContext() (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.Background(), rpcTimeout)
}

// GetID returns the ID of the remote cosigner
// Implements the cosigner interface
func (cosigner *RemoteCosigner) GetID() int {
	return cosigner.id
}

// GetAddress returns the P2P URL of the remote cosigner
// Implements the ICosigner interface
func (cosigner *RemoteCosigner) GetAddress() string {
	return cosigner.address
}

// GetPubKey returns public key of the validator.
// Implements Cosigner interface
func (cosigner *RemoteCosigner) GetPubKey(_ string) (cometcrypto.PubKey, error) {
	return nil, fmt.Errorf("unexpected call to RemoteCosigner.GetPubKey")
}

// VerifySignature validates a signed payload against the public key.
// Implements ICosigner interface
func (cosigner *RemoteCosigner) VerifySignature(_ string, _, _ []byte) bool {
	return false
}

func (cosigner *RemoteCosigner) getGRPCClient() (proto.ICosignerGRPCServerClient, *grpc.ClientConn, error) {
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
	return proto.NewICosignerGRPCServerClient(conn), conn, nil
}

// GetNonces implements the Cosigner interface
// It uses the gRPC client to request the nonces from the other
func (cosigner *RemoteCosigner) GetNonces(
	chainID string,
	req types.HRSTKey,
) (*NoncesResponse, error) {

	client, conn, err := cosigner.getGRPCClient()
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	context, cancelFunc := GetContext()
	defer cancelFunc()
	res, err := client.GetNonces(
		context,
		&proto.CosignerGRPCGetNoncesRequest{
			ChainID: chainID,
			Hrst:    req.ToProto(),
		},
	)
	if err != nil {
		return nil, err
	}
	return &NoncesResponse{
		Nonces: NoncesFromProto(res.GetNonces()),
	}, nil
}

// SetNoncesAndSign implements the Cosigner interface
// It acts as a client(!) and requests via gRPC the other
// "node's" LocalCosigner to set the nonces and sign the payload.
func (cosigner *RemoteCosigner) SetNoncesAndSign(
	req SetNoncesAndSignRequest) (*SignResponse, error) {
	client, conn, err := cosigner.getGRPCClient()
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	context, cancelFunc := GetContext()
	defer cancelFunc()
	res, err := client.SetNoncesAndSign(context,
		&proto.CosignerGRPCSetNoncesAndSignRequest{
			ChainID:   req.ChainID,
			Nonces:    WrappedNonces(req.Nonces).ToProto(),
			Hrst:      req.HRST.ToProto(),
			SignBytes: req.SignBytes,
		})
	if err != nil {
		return nil, err
	}
	return &SignResponse{
		NoncePublic: res.GetNoncePublic(),
		Timestamp:   time.Unix(0, res.GetTimestamp()),
		Signature:   res.GetSignature(),
	}, nil
}
