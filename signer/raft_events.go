package signer

import (
	"encoding/json"
	"errors"
	"fmt"

	proto "github.com/strangelove-ventures/horcrux/signer/proto"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

const (
	raftEventLSS = "LSS"
)

func (f *fsm) getEventHandler(key string) func(string) {
	return map[string]func(string){
		raftEventLSS: f.handleLSSEvent,
	}[key]
}

func (f *fsm) shouldRetain(key string) bool {
	// Last sign state handled as events only
	return key != raftEventLSS
}

func (f *fsm) handleLSSEvent(value string) {
	lss := &SignStateConsensus{}
	err := json.Unmarshal([]byte(value), lss)
	if err != nil {
		f.logger.Error("LSS Unmarshal Error", err.Error())
		return
	}
	_ = f.thresholdValidator.SaveLastSignedState(*lss)
	_ = f.cosigner.SaveLastSignedState(*lss)
}

func (s *RaftStore) getLeaderGRPCClient() (proto.CosignerGRPCClient, error) {
	leader := string(s.GetLeader())
	if leader == "" {
		return nil, errors.New("no current raft leader")
	}
	leaderAddress := fmt.Sprintf("tcp://%s", leader)
	conn, err := grpc.Dial(leaderAddress, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		return nil, err
	}
	return proto.NewCosignerGRPCClient(conn), nil
}

func (s *RaftStore) LeaderSignBlock(req CosignerSignBlockRequest) (*CosignerSignBlockResponse, error) {
	client, err := s.getLeaderGRPCClient()
	if err != nil {
		return nil, err
	}
	context, cancelFunc := getContext()
	defer cancelFunc()
	res, err := client.SignBlock(context, &proto.CosignerGRPCSignBlockRequest{
		ChainID: req.ChainID,
		Block:   req.Block.toProto(),
	})
	if err != nil {
		return nil, err
	}
	return &CosignerSignBlockResponse{
		Signature: res.GetSignature(),
	}, nil
}
