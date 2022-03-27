package signer

import (
	"context"
	"fmt"
	"time"

	"github.com/stranger-love/horcrux/signer/localthreshold"
	raft2 "github.com/stranger-love/horcrux/signer/raft"

	"github.com/hashicorp/raft"
	proto "github.com/stranger-love/horcrux/signer/proto"
)

type CosignerGRPCServer struct {
	cosigner           *localthreshold.LocalCosigner
	thresholdValidator *ThresholdValidator
	raftStore          *raft2.RaftStore
	proto.UnimplementedCosignerGRPCServer
}

func (rpc *CosignerGRPCServer) SignBlock(
	ctx context.Context, req *proto.CosignerGRPCSignBlockRequest) (*proto.CosignerGRPCSignBlockResponse, error) {
	block := &Block{
		Height:    req.Block.GetHeight(),
		Round:     req.Block.GetRound(),
		Step:      int8(req.Block.GetStep()),
		SignBytes: req.Block.GetSignBytes(),
		Timestamp: time.Unix(0, req.Block.GetTimestamp()),
	}
	res, _, err := rpc.thresholdValidator.SignBlock(req.ChainID, block)
	if err != nil {
		return nil, err
	}
	return &proto.CosignerGRPCSignBlockResponse{
		Signature: res,
	}, nil
}

func (rpc *CosignerGRPCServer) SetEphemeralSecretPartsAndSign(
	ctx context.Context,
	req *proto.CosignerGRPCSetEphemeralSecretPartsAndSignRequest,
) (*proto.CosignerGRPCSetEphemeralSecretPartsAndSignResponse, error) {
	res, err := rpc.cosigner.SetEphemeralSecretPartsAndSign(localthreshold.CosignerSetEphemeralSecretPartsAndSignRequest{
		EncryptedSecrets: localthreshold.CosignerEphemeralSecretPartsFromProto(req.GetEncryptedSecrets()),
		HRST:             localthreshold.HRSTKeyFromProto(req.GetHrst()),
		SignBytes:        req.GetSignBytes(),
	})
	if err != nil {
		return nil, err
	}
	return &proto.CosignerGRPCSetEphemeralSecretPartsAndSignResponse{
		EphemeralPublic: res.EphemeralPublic,
		Timestamp:       res.Timestamp.UnixNano(),
		Signature:       res.Signature,
	}, nil
}

func (rpc *CosignerGRPCServer) GetEphemeralSecretParts(
	ctx context.Context,
	req *proto.CosignerGRPCGetEphemeralSecretPartsRequest,
) (*proto.CosignerGRPCGetEphemeralSecretPartsResponse, error) {
	res, err := rpc.cosigner.GetEphemeralSecretParts(localthreshold.HRSTKeyFromProto(req.GetHrst()))
	if err != nil {
		return nil, err
	}
	return &proto.CosignerGRPCGetEphemeralSecretPartsResponse{
		EncryptedSecrets: localthreshold.CosignerEphemeralSecretParts(res.EncryptedSecrets).ToProto(),
	}, nil
}

func (rpc *CosignerGRPCServer) TransferLeadership(
	ctx context.Context,
	req *proto.CosignerGRPCTransferLeadershipRequest,
) (*proto.CosignerGRPCTransferLeadershipResponse, error) {
	leaderID := req.GetLeaderID()
	if leaderID != "" {
		for _, peer := range rpc.raftStore.Peers {
			thisPeerID := fmt.Sprint(peer.GetID())
			if thisPeerID == leaderID {
				peerRaftAddress := raft2.P2pURLToRaftAddress(peer.GetAddress())
				fmt.Printf("Transferring leadership to ID: %s - Address: %s\n", thisPeerID, peerRaftAddress)
				rpc.raftStore.Raft.LeadershipTransferToServer(raft.ServerID(thisPeerID), raft.ServerAddress(peerRaftAddress))
				return &proto.CosignerGRPCTransferLeadershipResponse{LeaderID: thisPeerID, LeaderAddress: peerRaftAddress}, nil
			}
		}
	}
	fmt.Printf("Transferring leadership to next candidate\n")
	rpc.raftStore.Raft.LeadershipTransfer()
	return &proto.CosignerGRPCTransferLeadershipResponse{}, nil
}
