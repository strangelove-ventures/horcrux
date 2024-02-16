package node

import (
	"encoding/json"

	"github.com/strangelove-ventures/horcrux/src/types"
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
	lss := &types.ChainSignStateConsensus{}
	err := json.Unmarshal([]byte(value), lss)
	if err != nil {
		f.logger.Error(
			"LastSignState Unmarshal Error",
			"error", err,
		)
		return
	}
	if err := f.thresholdValidator.LoadSignStateIfNecessary(lss.ChainID); err != nil {
		f.logger.Error(
			"Error loading sign state during raft replication",
			"chain_id", lss.ChainID,
			"error", err,
		)
		return
	}
	_ = f.thresholdValidator.SaveLastSignedState(lss.ChainID, lss.SignStateConsensus)
	_ = f.thresholdValidator.mpc.MyCosigner.SaveLastSignedState(lss.ChainID, lss.SignStateConsensus)
}
