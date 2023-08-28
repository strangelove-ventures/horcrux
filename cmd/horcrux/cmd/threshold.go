package cmd

import (
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/strangelove-ventures/horcrux/pkg/pcosigner"

	"github.com/strangelove-ventures/horcrux/pkg/node"

	cometlog "github.com/cometbft/cometbft/libs/log"
	cometservice "github.com/cometbft/cometbft/libs/service"
)

const maxWaitForSameBlockAttempts = 3

func NewThresholdValidator(
	logger cometlog.Logger,
) ([]cometservice.Service, *node.ThresholdValidator, error) {
	if err := config.Config.ValidateThresholdModeConfig(); err != nil {
		return nil, nil, err
	}

	thresholdCfg := config.Config.ThresholdModeConfig
	// NOTE: Shouldnt this be a list of concrete type instead of interface type?
	remoteCosigners := make([]node.ICosigner, 0, len(thresholdCfg.Cosigners)-1)

	var p2pListen string

	var security pcosigner.ICosignerSecurity
	var eciesErr error
	security, eciesErr = config.CosignerSecurityECIES()
	if eciesErr != nil {
		var rsaErr error
		security, rsaErr = config.CosignerSecurityRSA()
		if rsaErr != nil {
			return nil, nil, fmt.Errorf("failed to initialize cosigner ECIES / RSA security : %w / %w", eciesErr, rsaErr)
		}
	}

	for _, c := range thresholdCfg.Cosigners {
		if c.ShardID != security.GetID() {
			remoteCosigners = append(
				remoteCosigners,
				pcosigner.NewRemoteCosigner(c.ShardID, c.P2PAddr),
			)
		} else {
			p2pListen = c.P2PAddr
		}
	}

	if p2pListen == "" {
		return nil, nil, fmt.Errorf("cosigner config does not exist for our shard ID %d", security.GetID())
	}

	localCosigner := pcosigner.NewLocalCosigner(
		logger,
		&config,
		security,
		p2pListen,
	)

	// Validated prior in ValidateThresholdModeConfig
	grpcTimeout, _ := time.ParseDuration(thresholdCfg.GRPCTimeout)
	raftTimeout, _ := time.ParseDuration(thresholdCfg.RaftTimeout)

	raftDir := filepath.Join(config.HomeDir, "raft")
	if err := os.MkdirAll(raftDir, 0700); err != nil {
		return nil, nil, fmt.Errorf("error creating raft directory: %w", err)
	}

	// RAFT node ID is the cosigner ID
	nodeID := fmt.Sprint(security.GetID())

	// Start RAFT store listener
	raftStore := node.NewRaftStore(nodeID,
		raftDir, p2pListen, raftTimeout, logger)
	if err := raftStore.Start(); err != nil {
		return nil, nil, fmt.Errorf("error starting raft store: %w", err)
	}
	services := []cometservice.Service{raftStore}

	val := node.NewThresholdValidator(
		logger,
		&config,
		thresholdCfg.Threshold,
		grpcTimeout,
		maxWaitForSameBlockAttempts,
		localCosigner,
		remoteCosigners,
		raftStore, // raftStore implements the ILeader interface
	)

	raftStore.SetThresholdValidator(val)

	return services, val, nil
}
