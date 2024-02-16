package node

import (
	"context"
	"fmt"

	"github.com/strangelove-ventures/horcrux/src/types"

	"github.com/hashicorp/raft"
	"github.com/strangelove-ventures/horcrux/proto/strangelove/proto"
	// "github.com/strangelove-ventures/horcrux/src/proto"
)

/*
This is the NodeGRPCServer. It is the GRPC server for the node.
*/

// TODO: Remove this as we want NodeGRPCServer to NodeGRPCServer
var _ proto.NodeServiceServer = &NodeGRPCServer{}

// Client is the GRPC client for the node.
// Client implements the proto.NodeClient interface.
type Client struct {
	id      int    // Index of the cosigner
	address string // Address to the other nodes
	client  proto.NodeServiceClient
}

// NodeGRPCClient is the GRPC client for the node.
// NodeGRPCClient implements the proto.NodeClient interface.
type GRPCClient struct {
	// cosigner proto.CosignerClient
	Clients []Client
}

// NodeGRPCServer is the GRPC server for the node.
// NodeGRPCServer implements the proto.NodeServer interface.
type NodeGRPCServer struct {
	// We are not allowed to have a cosigner here as it is a circular dependency.
	// and cosigner should not be "connected to the node" only to themselves.
	// cosigner           *cosigner.LocalCosigner //Change to interface
	thresholdValidator *ThresholdValidator
	raftStore          *RaftStore // Our consensus algorithm
	// TODO: add logger and not rely on raftStore.logger

	// TODO: Decouple cosignerserver from nodeserver.
	// proto.UnimplementedCosignerServer
	proto.UnimplementedNodeServiceServer
}

func NewNodeGRPCServer(
	// cosigner *cosigner.LocalCosigner,
	thresholdValidator *ThresholdValidator,
	raftStore *RaftStore,
) *NodeGRPCServer {
	return &NodeGRPCServer{
		// cosigner:           cosigner,
		thresholdValidator: thresholdValidator,
		raftStore:          raftStore,
	}
}

// TransferLeadership transfers leadership to another candidate or to the next eligible candidate.
// TransferLeadership implements the proto.NodeServer interface.
func (rpc *NodeGRPCServer) TransferLeadership(
	_ context.Context,
	req *proto.TransferLeadershipRequest,
) (*proto.TransferLeadershipResponse, error) {
	if rpc.raftStore.raft.State() != raft.Leader {
		return &proto.TransferLeadershipResponse{}, nil
	}
	leaderID := req.GetLeaderID()
	if leaderID != "" {
		// TODO: Change to RPC call of ThresholdValidator
		for _, c := range rpc.thresholdValidator.mpc.peerCosigners {
			shardIndex := fmt.Sprint(c.GetIndex())
			if shardIndex == leaderID {
				raftAddress := p2pURLToRaftAddress(c.GetAddress())
				// TODO: Change to logging
				fmt.Printf("Transferring leadership to Index: %s - Address: %s\n", shardIndex, raftAddress)
				rpc.raftStore.raft.LeadershipTransferToServer(raft.ServerID(shardIndex), raft.ServerAddress(raftAddress))
				return &proto.TransferLeadershipResponse{LeaderID: shardIndex, LeaderAddress: raftAddress}, nil
			}
		}
	}
	fmt.Printf("Transferring leadership to next candidate\n")
	rpc.raftStore.raft.LeadershipTransfer()
	return &proto.TransferLeadershipResponse{}, nil
}

// SignBlock imlements the proto.NodeServer interface.
func (rpc *NodeGRPCServer) SignBlock(
	ctx context.Context,
	req *proto.SignBlockRequest,
) (*proto.SignBlockResponse, error) {
	// The local signs the block

	res, _, err := rpc.thresholdValidator.Sign(ctx, req.ChainID, types.BlockFromProto(req.Block))
	if err != nil {
		return nil, err
	}
	return &proto.SignBlockResponse{
		Signature: res,
	}, nil
}

// GetLeader implements the proto.NodeServer interface.
func (rpc *NodeGRPCServer) GetLeader(
	context.Context,
	*proto.GetLeaderRequest,
) (*proto.GetLeaderResponse, error) {
	leader := rpc.raftStore.GetLeader()
	return &proto.GetLeaderResponse{Leader: int32(leader)}, nil
}

/* ALL BELOW THIS LINE IS SHOULD BE MOVED TO COSIGNER
func (rpc *NodeGRPCServer) GetNonces(
	ctx context.Context,
	req *proto.GetNoncesRequest,
	) (*proto.GetNoncesResponse, error) {
		uuids := make([]uuid.UUID, len(req.Uuids))
		for i, uuidBytes := range req.Uuids {
			uuids[i] = uuid.UUID(uuidBytes)
		}
		res, err := rpc.thresholdValidator.MyCosigner.GetNonces(
			ctx,
			uuids,
		)
		if err != nil {
			return nil, err
		}

	return &proto.GetNoncesResponse{
		Nonces: res.ToProto(),
		}, nil
	}

	// TODO: Move to cosigner server
	func (rpc *NodeGRPCServer) SetNoncesAndSign(
		ctx context.Context,
		req *proto.SetNoncesAndSignRequest,
		) (*proto.SetNoncesAndSignResponse, error) {
			res, err := rpc.thresholdValidator.MyCosigner.SetNoncesAndSign(ctx, cosigner.CosignerSetNoncesAndSignRequest{
				ChainID: req.ChainID,
				Nonces: &cosigner.CosignerUUIDNonces{
					UUID:   uuid.UUID(req.Uuid),
					Nonces: cosigner.FromProtoToNonces(req.GetNonces()),
				},
				HRST:      types.HRSTFromProto(req.GetHrst()),
		SignBytes: req.GetSignBytes(),
	})
	if err != nil {
		rpc.raftStore.logger.Error(
			"Failed to sign with shard",
			"chain_id", req.ChainID,
			"height", req.Hrst.Height,
			"round", req.Hrst.Round,
			"step", req.Hrst.Step,
			"error", err,
		)
		return nil, err
	}
	rpc.raftStore.logger.Info(
		"Signed with shard",
		"chain_id", req.ChainID,
		"height", req.Hrst.Height,
		"round", req.Hrst.Round,
		"step", req.Hrst.Step,
	)
	return &proto.SetNoncesAndSignResponse{
		NoncePublic: res.NoncePublic,
		Timestamp:   res.Timestamp.UnixNano(),
		Signature:   res.Signature,
		}, nil
}

func (rpc *NodeGRPCServer) Ping(context.Context, *proto.PingRequest) (*proto.PingResponse, error) {
	return &proto.PingResponse{}, nil
}

*/
