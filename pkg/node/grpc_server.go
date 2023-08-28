package node

import (
	"context"
	"fmt"
	"time"

	"github.com/strangelove-ventures/horcrux/pkg/pcosigner"
	"github.com/strangelove-ventures/horcrux/pkg/types"

	"github.com/hashicorp/raft"
	"github.com/strangelove-ventures/horcrux/pkg/proto"
)

// Enures that GRPCServer implements the proto.CosignerGRPCServer interface.
var _ proto.ICosignerGRPCServerServer = &GRPCServer{}

type GRPCServer struct {
	cosigner           *pcosigner.LocalCosigner // The "node's" LocalCosigner
	thresholdValidator *ThresholdValidator      // The "node's" ThresholdValidator
	raftStore          *RaftStore               // The "node's" RaftStore
	// Promoted Fields is embedded to have forward compatiblitity
	proto.UnimplementedICosignerGRPCServerServer
}

// NewGRPCServer returns a new GRPCServer.
func NewGRPCServer(
	cosigner *pcosigner.LocalCosigner,
	thresholdValidator *ThresholdValidator,
	raftStore *RaftStore,
) *GRPCServer {
	return &GRPCServer{
		// TODO: This is a hack to get around the fact that the cosigner is not a?
		cosigner:           cosigner,
		thresholdValidator: thresholdValidator,
		raftStore:          raftStore,
	}
}

// SignBlock "pseudo-implements" the ICosignerGRPCServer interface in pkg/proto/cosigner_grpc_server_grpc.pb.go
func (rpc *GRPCServer) SignBlock(
	_ context.Context,
	req *proto.CosignerGRPCSignBlockRequest,
) (*proto.CosignerGRPCSignBlockResponse, error) {
	block := &Block{
		Height:    req.Block.GetHeight(),
		Round:     req.Block.GetRound(),
		Step:      int8(req.Block.GetStep()),
		SignBytes: req.Block.GetSignBytes(),
		Timestamp: time.Unix(0, req.Block.GetTimestamp()),
	}
	// this
	res, _, err := rpc.thresholdValidator.SignBlock(req.ChainID, block)
	if err != nil {
		return nil, err
	}
	return &proto.CosignerGRPCSignBlockResponse{
		Signature: res,
	}, nil
}

func (rpc *GRPCServer) SetNoncesAndSign(
	_ context.Context,
	req *proto.CosignerGRPCSetNoncesAndSignRequest,
) (*proto.CosignerGRPCSetNoncesAndSignResponse, error) {
	res, err := rpc.cosigner.SetNoncesAndSign(
		pcosigner.CosignerSetNoncesAndSignRequest{
			ChainID:   req.ChainID,
			Nonces:    pcosigner.CosignerNoncesFromProto(req.GetNonces()),
			HRST:      types.HRSTKeyFromProto(req.GetHrst()),
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
	return &proto.CosignerGRPCSetNoncesAndSignResponse{
		NoncePublic: res.NoncePublic,
		Timestamp:   res.Timestamp.UnixNano(),
		Signature:   res.Signature,
	}, nil
}

// GetNonces implements the ICosignerGRPCServer interface.
func (rpc *GRPCServer) GetNonces(
	_ context.Context,
	req *proto.CosignerGRPCGetNoncesRequest,
) (*proto.CosignerGRPCGetNoncesResponse, error) {
	res, err := rpc.cosigner.GetNonces(
		req.ChainID,
		types.HRSTKeyFromProto(req.GetHrst()),
	)
	if err != nil {
		return nil, err
	}
	return &proto.CosignerGRPCGetNoncesResponse{
		Nonces: pcosigner.CosignerNonces(res.Nonces).ToProto(),
	}, nil
}

// TransferLeadership pseudo-implements the ICosignerGRPCServer interface in pkg/proto/cosigner_grpc_server_grpc.pb.go
func (rpc *GRPCServer) TransferLeadership(
	_ context.Context,
	req *proto.CosignerGRPCTransferLeadershipRequest,
) (*proto.CosignerGRPCTransferLeadershipResponse, error) {
	if rpc.raftStore.raft.State() != raft.Leader {
		return &proto.CosignerGRPCTransferLeadershipResponse{}, nil
	}
	leaderID := req.GetLeaderID()
	if leaderID != "" {
		for _, c := range rpc.raftStore.thresholdValidator.peerCosigners {
			shardID := fmt.Sprint(c.GetID())
			if shardID == leaderID {
				raftAddress := p2pURLToRaftAddress(c.GetAddress())
				fmt.Printf("Transferring leadership to ID: %s - Address: %s\n", shardID, raftAddress)
				rpc.raftStore.raft.LeadershipTransferToServer(raft.ServerID(shardID), raft.ServerAddress(raftAddress))
				return &proto.CosignerGRPCTransferLeadershipResponse{LeaderID: shardID, LeaderAddress: raftAddress}, nil
			}
		}
	}
	fmt.Printf("Transferring leadership to next candidate\n")
	rpc.raftStore.raft.LeadershipTransfer()
	return &proto.CosignerGRPCTransferLeadershipResponse{}, nil
}

// GetLeader pseudo-implements the ICosignerGRPCServer interface in pkg/proto/cosigner_grpc_server_grpc.pb.go
// GetLeader gets the current raft cluster leader and send it as respons.
func (rpc *GRPCServer) GetLeader(
	context.Context,
	*proto.CosignerGRPCGetLeaderRequest,
) (*proto.CosignerGRPCGetLeaderResponse, error) {
	leader := rpc.raftStore.GetLeader()
	return &proto.CosignerGRPCGetLeaderResponse{Leader: string(leader)}, nil
}
