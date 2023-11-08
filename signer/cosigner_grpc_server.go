package signer

import (
	"context"
	"fmt"

	"github.com/hashicorp/raft"
	"github.com/strangelove-ventures/horcrux/signer/proto"
)

var _ proto.CosignerServer = &CosignerGRPCServer{}

type CosignerGRPCServer struct {
	cosigner           *LocalCosigner
	thresholdValidator *ThresholdValidator
	raftStore          *RaftStore
	proto.UnimplementedCosignerServer
}

func NewCosignerGRPCServer(
	cosigner *LocalCosigner,
	thresholdValidator *ThresholdValidator,
	raftStore *RaftStore,
) *CosignerGRPCServer {
	return &CosignerGRPCServer{
		cosigner:           cosigner,
		thresholdValidator: thresholdValidator,
		raftStore:          raftStore,
	}
}

func (rpc *CosignerGRPCServer) SignBlock(
	_ context.Context,
	req *proto.SignBlockRequest,
) (*proto.SignBlockResponse, error) {
	res, _, err := rpc.thresholdValidator.SignBlock(req.ChainID, BlockFromProto(req.Block))
	if err != nil {
		return nil, err
	}
	return &proto.SignBlockResponse{
		Signature: res,
	}, nil
}

func (rpc *CosignerGRPCServer) SetNoncesAndSign(
	_ context.Context,
	req *proto.SetNoncesAndSignRequest,
) (*proto.SetNoncesAndSignResponse, error) {
	res, err := rpc.cosigner.SetNoncesAndSign(CosignerSetNoncesAndSignRequest{
		ChainID:   req.ChainID,
		Nonces:    CosignerNoncesFromProto(req.GetNonces()),
		HRST:      HRSTKeyFromProto(req.GetHrst()),
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

func (rpc *CosignerGRPCServer) GetNonces(
	_ context.Context,
	req *proto.GetNoncesRequest,
) (*proto.GetNoncesResponse, error) {
	res, err := rpc.cosigner.GetNonces(
		req.ChainID,
		HRSTKeyFromProto(req.GetHrst()),
	)
	if err != nil {
		return nil, err
	}
	return &proto.GetNoncesResponse{
		Nonces: CosignerNonces(res.Nonces).toProto(),
	}, nil
}

func (rpc *CosignerGRPCServer) TransferLeadership(
	_ context.Context,
	req *proto.TransferLeadershipRequest,
) (*proto.TransferLeadershipResponse, error) {
	if rpc.raftStore.raft.State() != raft.Leader {
		return &proto.TransferLeadershipResponse{}, nil
	}
	leaderID := req.GetLeaderID()
	if leaderID != "" {
		for _, c := range rpc.raftStore.Cosigners {
			shardID := fmt.Sprint(c.GetID())
			if shardID == leaderID {
				raftAddress := p2pURLToRaftAddress(c.GetAddress())
				fmt.Printf("Transferring leadership to ID: %s - Address: %s\n", shardID, raftAddress)
				rpc.raftStore.raft.LeadershipTransferToServer(raft.ServerID(shardID), raft.ServerAddress(raftAddress))
				return &proto.TransferLeadershipResponse{LeaderID: shardID, LeaderAddress: raftAddress}, nil
			}
		}
	}
	fmt.Printf("Transferring leadership to next candidate\n")
	rpc.raftStore.raft.LeadershipTransfer()
	return &proto.TransferLeadershipResponse{}, nil
}

func (rpc *CosignerGRPCServer) GetLeader(
	context.Context,
	*proto.GetLeaderRequest,
) (*proto.GetLeaderResponse, error) {
	leader := rpc.raftStore.GetLeader()
	return &proto.GetLeaderResponse{Leader: string(leader)}, nil
}
