package signer

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
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

func (s *RaftStore) getLeaderRPCAddress() (string, error) {
	leader := string(s.GetLeader())
	if leader == "" {
		return "", errors.New("no current raft leader")
	}
	// If the same RPC port is used for all peers, we can just use the leader address on that port
	if s.commonRPCPort != "" {
		leaderSplit := strings.Split(leader, ":")
		if len(leaderSplit) == 2 {
			return fmt.Sprintf("tcp://%s:%s", leaderSplit[0], s.commonRPCPort), nil
		}
	}
	for _, peer := range s.Peers {
		if peer.GetRaftAddress() == leader {
			return peer.GetAddress(), nil
		}
		tcpAddress, err := GetTCPAddressForRaftAddress(peer.GetRaftAddress())
		if err != nil {
			continue
		}
		if fmt.Sprint(tcpAddress) == leader {
			return peer.GetAddress(), nil
		}
	}

	return "", fmt.Errorf("unable to find leader cosigner from address %s", leader)
}

func (s *RaftStore) LeaderSignBlock(req CosignerSignBlockRequest) (res *CosignerSignBlockResponse, err error) {
	leaderCosigner, err := s.getLeaderRPCAddress()
	if err != nil {
		return nil, err
	}

	return res, CallRPC(leaderCosigner, "SignBlock", req, &res)
}
