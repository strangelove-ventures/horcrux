package node

import (
	"github.com/strangelove-ventures/horcrux/proto/strangelove/proto"
	// "github.com/strangelove-ventures/horcrux/src/proto"
)

// var _ Cosigner = &RemoteCosigner{}

// CosignerClient uses CosignerGRPC to request signing from a remote cosigner
// Remote Cosigner are CLIENTS! to every other cosigner, including the the nodes local cosigner
// It calls the GRPC server of the other cosigner
// TODO: Change name to CosignerClient
type NodeClient struct {
	id      int
	address string

	Client proto.NodeServiceClient // GRPC Client
}

// Placeholder function because of testing
// TODO: Change name to InitCosignerClient
func InitThresholdClient(id int, address string, client proto.NodeServiceClient) *NodeClient {
	nodeclient := &NodeClient{
		id:      id,
		address: address, // address is the P2P URL of the remote cosigner
		Client:  client,
	}
	return nodeclient
}
