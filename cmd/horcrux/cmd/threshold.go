package cmd

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"time"

	cconfig "github.com/strangelove-ventures/horcrux/src/config"
	"github.com/strangelove-ventures/horcrux/src/cosigner"
	"github.com/strangelove-ventures/horcrux/src/cosigner/nodesecurity"
	"github.com/strangelove-ventures/horcrux/src/node"

	cometlog "github.com/cometbft/cometbft/libs/log"
	cometservice "github.com/cometbft/cometbft/libs/service"
)

const maxWaitForSameBlockAttempts = 3

func CosignerSecurityECIES(c cconfig.RuntimeConfig) (*nodesecurity.CosignerSecurityECIES, error) {
	keyFile, err := c.KeyFileExistsCosignerECIES()
	if err != nil {
		return nil, err
	}

	key, err := nodesecurity.LoadCosignerECIESKey(keyFile)
	if err != nil {
		return nil, fmt.Errorf("error reading cosigner key (%s): %w", keyFile, err)
	}

	return nodesecurity.NewCosignerSecurityECIES(key), nil
}

func CosignerSecurityRSA(c cconfig.RuntimeConfig) (*nodesecurity.CosignerSecurityRSA, error) {
	keyFile, err := c.KeyFileExistsCosignerRSA()
	if err != nil {
		return nil, err
	}

	key, err := nodesecurity.LoadCosignerRSAKey(keyFile)
	if err != nil {
		return nil, fmt.Errorf("error reading cosigner key (%s): %w", keyFile, err)
	}

	return nodesecurity.NewCosignerSecurityRSA(key), nil
}

// TODO: Single Responsibility Principle :(
func NewThresholdValidator(
	ctx context.Context,
	logger cometlog.Logger,
) ([]cometservice.Service, *node.ThresholdValidator, error) {
	if err := config.Config.ValidateThresholdModeConfig(); err != nil {
		return nil, nil, err
	}

	thresholdCfg := config.Config.ThresholdModeConfig

	remoteCosigners := make([]node.ICosigner, 0, len(thresholdCfg.Cosigners)-1)

	var p2pListen string

	var security cosigner.ICosignerSecurity
	var eciesErr error
	// TODO: This is really ugly and should be refactored
	security, eciesErr = CosignerSecurityECIES(config)
	if eciesErr != nil {
		var rsaErr error
		security, rsaErr = CosignerSecurityRSA(config)
		if rsaErr != nil {
			return nil, nil, fmt.Errorf("failed to initialize cosigner ECIES / RSA security : %w / %w", eciesErr, rsaErr)
		}
	}

	for _, c := range thresholdCfg.Cosigners {
		if c.ShardID != security.GetID() {
			rc, err := cosigner.NewCosignerClient(c.ShardID, c.P2PAddr)
			if err != nil {
				return nil, nil, fmt.Errorf("failed to initialize remote cosigner: %w", err)
			}
			remoteCosigners = append(
				remoteCosigners,
				rc,
			)
		} else {
			p2pListen = c.P2PAddr
		}
	}

	if p2pListen == "" {
		return nil, nil, fmt.Errorf("cosigner config does not exist for our shard Index %d", security.GetID())
	}

	localCosigner := cosigner.NewLocalCosigner(
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

	// RAFT node ID is the cosigner id
	nodeID := fmt.Sprint(security.GetID())

	// Start RAFT store listener
	raftStore := node.NewRaftStore(nodeID,
		raftDir, p2pListen, raftTimeout, logger, localCosigner, remoteCosigners)
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
		raftStore,
	)

	raftStore.SetThresholdValidator(val, localCosigner)

	if err := val.Start(ctx); err != nil {
		return nil, nil, fmt.Errorf("failed to start threshold validator: %w", err)
	}

	return services, val, nil
}
