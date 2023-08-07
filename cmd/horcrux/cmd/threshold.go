package cmd

import (
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/strangelove-ventures/horcrux/pkg/signer"

	cometlog "github.com/cometbft/cometbft/libs/log"
	cometservice "github.com/cometbft/cometbft/libs/service"
)

const maxWaitForSameBlockAttempts = 3

func NewThresholdValidator(
	logger cometlog.Logger,
) ([]cometservice.Service, *signer.ThresholdValidator, error) {
	if err := config.Config.ValidateThresholdModeConfig(); err != nil {
		return nil, nil, err
	}

	thresholdCfg := config.Config.ThresholdModeConfig

	remoteCosigners := make([]signer.Cosigner, 0, len(thresholdCfg.Cosigners)-1)

	var p2pListen string

	var security signer.CosignerSecurity
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
				signer.NewRemoteCosigner(c.ShardID, c.P2PAddr),
			)
		} else {
			p2pListen = c.P2PAddr
		}
	}

	if p2pListen == "" {
		return nil, nil, fmt.Errorf("cosigner config does not exist for our shard ID %d", security.GetID())
	}

	localCosigner := signer.NewLocalCosigner(
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
		maxWaitForSameBlockAttempts,
		localCosigner,
		remoteCosigners,
		raftStore,
	)

	raftStore.SetThresholdValidator(val)

	return services, val, nil
}
