package signer

import (
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/hashicorp/raft"
)

const (
	raftEventHRS = "HRS"
	raftEventLSS = "LSS"
)

func (f *fsm) getEventHandler(key string) func(string) {
	return map[string]func(string){
		raftEventHRS: f.handleHRSEvent,
		raftEventLSS: f.handleLSSEvent,
	}[key]
}

func (s *RaftStore) isOldEphemeralShareReceipt(key string) bool {
	if len(key) >= 9 && key[:8] == "EphDone." {
		keySplit := strings.Split(key, ".")
		height, err := strconv.ParseInt(keySplit[1], 10, 64)
		if err != nil {
			return true
		}
		round, err := strconv.ParseInt(keySplit[2], 10, 64)
		if err != nil {
			return true
		}
		step, err := strconv.ParseInt(keySplit[3], 10, 8)
		if err != nil {
			return true
		}
		err = s.thresholdValidator.GetErrorIfLessOrEqual(height, round, int8(step))
		if err != nil {
			return true
		}
	}
	return false
}

func (f *fsm) shouldRetain(key string) bool {
	// HRS are handled as events only
	if key == raftEventHRS {
		return false
	}

	// Last sign state handled as events only
	if key == raftEventLSS {
		return false
	}

	// Drop receipts for old HRS
	if (*RaftStore)(f).isOldEphemeralShareReceipt(key) {
		return false
	}
	return true
}

func (f *fsm) shareEphemeralSecretPartsWithPeer(peer Cosigner, hrsKey *HRSKey) {
	ephemeralSecretPart, err := f.cosigner.GetEphemeralSecretPart(CosignerGetEphemeralSecretPartRequest{
		ID:     peer.GetID(),
		Height: hrsKey.Height,
		Round:  hrsKey.Round,
		Step:   hrsKey.Step,
	})
	if err != nil {
		f.logger.Error("GetEphemeralSecretPart error", err.Error())
		return
	}

	err = peer.SetEphemeralSecretPart(ephemeralSecretPart)
	if err != nil {
		f.logger.Error("SetEphemeralSecretPart Error", err.Error())
	}
}

func (f *fsm) handleHRSEvent(value string) {
	hrsKey := &HRSKey{}
	err := json.Unmarshal([]byte(value), hrsKey)
	if err != nil {
		f.logger.Error("HRS Unmarshal Error", err.Error())
		return
	}
	err = f.thresholdValidator.GetErrorIfLessOrEqual(hrsKey.Height, hrsKey.Round, hrsKey.Step)
	if err != nil {
		f.logger.Error("Error with requested HRS", err.Error())
		return
	}

	for _, peer := range f.Peers {
		peerID := peer.GetID()
		// needed since we are included in peers
		if peerID == f.cosigner.GetID() {
			continue
		}
		go f.shareEphemeralSecretPartsWithPeer(peer, hrsKey)
	}
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

func (s *RaftStore) leaderEmitEphemeralSecretPartReceipt(
	req CosignerEmitEphemeralSecretReceiptRequest) error {
	doneSharingKey := fmt.Sprintf("EphDone.%d.%d.%d.%d.%d",
		req.HRS.Height, req.HRS.Round, req.HRS.Step, req.DestinationID, req.SourceID)
	if err := s.Set(doneSharingKey, "true"); err != nil {
		return err
	}
	return nil
}

func (s *RaftStore) EmitEphemeralSecretPartReceipt(
	req CosignerEmitEphemeralSecretReceiptRequest) error {
	if s.raft.State() == raft.Leader {
		return s.leaderEmitEphemeralSecretPartReceipt(req)
	}
	leaderCosigner, err := s.GetLeaderCosigner()
	if err != nil {
		return err
	}
	err = leaderCosigner.EmitEphemeralSecretPartReceipt(req)
	return err
}

func (s *RaftStore) PeriodicTrim() {
	for {
		time.Sleep(1 * time.Minute)
		s.logger.Debug(fmt.Sprintf("Pre-trim key value store size: %d\n", len(s.m)))
		for key := range s.m {
			if s.isOldEphemeralShareReceipt(key) {
				_ = s.Delete(key)
			}
		}
		time.Sleep(10 * time.Second)
		s.logger.Debug(fmt.Sprintf("Post trim key value store size: %d\n", len(s.m)))
	}
}
