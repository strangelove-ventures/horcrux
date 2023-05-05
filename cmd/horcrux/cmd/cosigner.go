package cmd

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	cometlog "github.com/cometbft/cometbft/libs/log"
	cometservice "github.com/cometbft/cometbft/libs/service"
	"github.com/cosmos/cosmos-sdk/types/bech32"
	"github.com/spf13/cobra"
	"github.com/strangelove-ventures/horcrux/signer"
)

func cosignerCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "cosigner",
		Short: "Threshold mpc signer for TM based nodes",
	}

	cmd.AddCommand(startCosignerCmd())
	cmd.AddCommand(addressCmd())

	return cmd
}

type AddressCmdOutput struct {
	HexAddress        string
	PubKey            string
	ValConsAddress    string
	ValConsPubAddress string
}

func addressCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:          "address chain-id [bech32]",
		Short:        "Get public key hex address and valcons address",
		Example:      `horcrux cosigner address cosmos`,
		SilenceUsage: true,
		Args:         cobra.RangeArgs(1, 2),
		RunE: func(cmd *cobra.Command, args []string) error {
			err := config.Config.ValidateThresholdModeConfig()
			if err != nil {
				return err
			}

			keyFile, err := config.KeyFileExistsCosigner(args[0])
			if err != nil {
				return err
			}

			key, err := signer.LoadCosignerEd25519Key(keyFile)
			if err != nil {
				return fmt.Errorf("error reading cosigner key: %s", err)
			}

			pubKey := key.PubKey
			pubKeyAddress := pubKey.Address()

			pubKeyJSON, err := signer.PubKey("", pubKey)
			if err != nil {
				return err
			}

			output := AddressCmdOutput{
				HexAddress: strings.ToUpper(hex.EncodeToString(pubKeyAddress)),
				PubKey:     pubKeyJSON,
			}

			if len(args) == 2 {
				bech32ValConsAddress, err := bech32.ConvertAndEncode(args[1]+"valcons", pubKeyAddress)
				if err != nil {
					return err
				}
				output.ValConsAddress = bech32ValConsAddress
				pubKeyBech32, err := signer.PubKey(args[1], pubKey)
				if err != nil {
					return err
				}
				output.ValConsPubAddress = pubKeyBech32
			} else {
				bech32Hint := "Pass bech32 base prefix as argument to generate (e.g. cosmos)"
				output.ValConsAddress = bech32Hint
				output.ValConsPubAddress = bech32Hint
			}

			jsonOut, err := json.Marshal(output)
			if err != nil {
				return err
			}

			fmt.Println(string(jsonOut))

			return nil
		},
	}

	return cmd
}

func startCosignerCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:          "start",
		Short:        "Start cosigner process",
		Args:         cobra.NoArgs,
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := signer.RequireNotRunning(config.PidFile); err != nil {
				return err
			}

			if err := config.Config.ValidateThresholdModeConfig(); err != nil {
				return err
			}

			out := cmd.OutOrStdout()

			logger := cometlog.NewTMLogger(cometlog.NewSyncWriter(out)).With("module", "validator")

			logger.Info(
				"CometBFT Validator",
				"mode", "threshold",
				"priv-state-dir", config.StateDir,
			)

			keyFile, err := config.KeyFileExistsCosignerRSA()
			if err != nil {
				return err
			}

			logger.Info(
				"CometBFT Validator",
				"mode", "threshold",
				"priv-state-dir", config.StateDir,
			)

			key, err := signer.LoadCosignerRSAKey(keyFile)
			if err != nil {
				return fmt.Errorf("error reading cosigner key (%s): %w", keyFile, err)
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
				return fmt.Errorf("cosigner config does not exist for our shard ID %d", key.ID)
			}

			localCosigner := signer.NewLocalCosigner(
				&config,
				key,
				pubKeys,
				p2pListen,
				uint8(thresholdCfg.Threshold),
			)

			// Validated prior in ValidateThresholdModeConfig
			grpcTimeout, _ := time.ParseDuration(thresholdCfg.GRPCTimeout)
			raftTimeout, _ := time.ParseDuration(thresholdCfg.RaftTimeout)

			raftDir := filepath.Join(config.HomeDir, "raft")
			if err := os.MkdirAll(raftDir, 0700); err != nil {
				return fmt.Errorf("error creating raft directory: %w", err)
			}

			// RAFT node ID is the cosigner ID
			nodeID := fmt.Sprint(key.ID)

			// Start RAFT store listener
			raftStore := signer.NewRaftStore(nodeID,
				raftDir, p2pListen, raftTimeout, logger, localCosigner, remoteCosigners)
			if err := raftStore.Start(); err != nil {
				return fmt.Errorf("error starting raft store: %w", err)
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

			go EnableDebugAndMetrics(cmd.Context(), out)

			services, err = signer.StartRemoteSigners(services, logger, val, config.Config.Nodes())
			if err != nil {
				return fmt.Errorf("failed to start remote signer(s): %w", err)
			}

			signer.WaitAndTerminate(logger, services, config.PidFile)

			return nil
		},
	}

	return cmd
}
