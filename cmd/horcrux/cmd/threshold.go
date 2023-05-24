package cmd

import (
	"fmt"
	"os"
	"path/filepath"
	"time"

	cometlog "github.com/cometbft/cometbft/libs/log"
	cometservice "github.com/cometbft/cometbft/libs/service"
	"github.com/strangelove-ventures/horcrux/signer"
)

func NewThresholdValidator(
	logger cometlog.Logger,
) ([]cometservice.Service, *signer.ThresholdValidator, error) {
	if err := config.Config.ValidateThresholdModeConfig(); err != nil {
		return nil, nil, err
	}

	keyFile, err := config.KeyFileExistsCosignerRSA()
	if err != nil {
		return nil, nil, err
	}

	key, err := signer.LoadCosignerRSAKey(keyFile)
	if err != nil {
		return nil, nil, fmt.Errorf("error reading cosigner key (%s): %w", keyFile, err)
	}

	thresholdCfg := config.Config.ThresholdModeConfig

	remoteCosigners := make([]signer.Cosigner, 0, len(thresholdCfg.Cosigners)-1)
	pubKeys := make([]signer.CosignerRSAPubKey, len(thresholdCfg.Cosigners))

	var p2pListen string

	for i, c := range thresholdCfg.Cosigners {
		if c.ShardID != key.ID {
			remoteCosigners = append(
				remoteCosigners,
				signer.NewRemoteCosigner(c.ShardID, c.P2PAddr),
			)
		} else {
			p2pListen = c.P2PAddr
		}

		pubKeys[i] = signer.CosignerRSAPubKey{
			ID:        c.ShardID,
			PublicKey: *key.RSAPubs[c.ShardID-1],
		}
	}

	if p2pListen == "" {
		return nil, nil, fmt.Errorf("cosigner config does not exist for our shard ID %d", key.ID)
	}

	localCosigner := signer.NewLocalCosigner(
		&config,
		key,
		pubKeys,
		p2pListen,
		thresholdCfg.Threshold,
	)

	// Validated prior in ValidateThresholdModeConfig
	grpcTimeout, _ := time.ParseDuration(thresholdCfg.GRPCTimeout)
	raftTimeout, _ := time.ParseDuration(thresholdCfg.RaftTimeout)

	raftDir := filepath.Join(config.HomeDir, "raft")
	if err := os.MkdirAll(raftDir, 0700); err != nil {
		return nil, nil, fmt.Errorf("error creating raft directory: %w", err)
	}

	// RAFT node ID is the cosigner ID
	nodeID := fmt.Sprint(key.ID)

	// Start RAFT store listener
	raftStore := signer.NewRaftStore(nodeID,
		raftDir, p2pListen, raftTimeout, logger, localCosigner, remoteCosigners)
	if err := raftStore.Start(); err != nil {
		return nil, nil, fmt.Errorf("error starting raft store: %w", err)
	}
	services := []cometservice.Service{raftStore}

	val := signer.NewThresholdValidator(
		logger,
		&config,
		thresholdCfg.Threshold,
		grpcTimeout,
		localCosigner,
		remoteCosigners,
		raftStore,
	)

	raftStore.SetThresholdValidator(val)

	return services, val, nil
}
