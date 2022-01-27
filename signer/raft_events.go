package signer

import (
	"encoding/json"
	"errors"
	"fmt"
	"net"
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

func (s *RaftStore) GetLeaderCosigner() (Cosigner, error) {
	leader := string(s.GetLeader())
	for _, peer := range s.Peers {
		peerSplit := strings.Split(peer.GetRaftAddress(), ":")
		ips, err := net.LookupIP(peerSplit[0])
		if err == nil {
			for _, ip := range ips {
				peerAddress := fmt.Sprintf("%s:%s", ip, peerSplit[1])
				if peerAddress == leader {
					return peer, nil
				}
			}
		} else if peer.GetAddress() == leader {
			return peer, nil
		}
	}
	return nil, errors.New("unable to find leader address")
}

func (s *RaftStore) LeaderSignBlock(req CosignerSignBlockRequest) (*CosignerSignBlockResponse, error) {
	leaderCosigner, err := s.GetLeaderCosigner()
	if err != nil {
		return nil, err
	}
	res, err := leaderCosigner.SignBlock(req)
	return &res, err
}
