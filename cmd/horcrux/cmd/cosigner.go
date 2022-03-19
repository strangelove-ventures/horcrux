package cmd

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path"
	"strings"
	"time"

	"github.com/cosmos/cosmos-sdk/types/bech32"
	"github.com/spf13/cobra"
	"github.com/strangelove-ventures/horcrux/signer"
	tmlog "github.com/tendermint/tendermint/libs/log"
	tmService "github.com/tendermint/tendermint/libs/service"
	"github.com/tendermint/tendermint/types"
)

func init() {
	cosignerCmd.AddCommand(StartCosignerCmd())
	cosignerCmd.AddCommand(AddressCmd())
	rootCmd.AddCommand(cosignerCmd)
}

var cosignerCmd = &cobra.Command{
	Use:   "cosigner",
	Short: "Threshold mpc signer for TM based nodes",
}

type AddressCmdOutput struct {
	HexAddress     string
	ValConsAddress string
}

func AddressCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "address",
		Short: "Get public key hex address and valcons address",
		Args:  cobra.RangeArgs(0, 1),
		RunE: func(cmd *cobra.Command, args []string) (err error) {
			err = validateCosignerConfig(config)
			if err != nil {
				return
			}

			var privValKeyFile string
			if config.PrivValKeyFile == "" {
				privValKeyFile = path.Join(config.HomeDir, "share.json")
			} else {
				privValKeyFile = config.PrivValKeyFile
			}

			key, err := signer.LoadCosignerKey(privValKeyFile)
			if err != nil {
				return fmt.Errorf("error reading cosigner key: %s", err)
			}

			pubKey := key.PubKey.Address()

			output := AddressCmdOutput{
				HexAddress: strings.ToUpper(hex.EncodeToString(pubKey)),
			}

			if len(args) == 1 {
				bech32ValConsAddress, err := bech32.ConvertAndEncode(args[0], pubKey)
				if err != nil {
					return err
				}
				output.ValConsAddress = bech32ValConsAddress
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

func StartCosignerCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "start",
		Short: "Start cosigner process",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) (err error) {
			err = validateCosignerConfig(config)
			if err != nil {
				return
			}

			var (
				// services to stop on shutdown
				services []tmService.Service
				pv       types.PrivValidator
				chainID  = config.ChainID
				logger   = tmlog.NewTMLogger(tmlog.NewSyncWriter(os.Stdout)).With("module", "validator")
				cfg      signer.Config
			)

			var privValKeyFile string
			if config.PrivValKeyFile == "" {
				privValKeyFile = path.Join(config.HomeDir, "share.json")
			} else {
				privValKeyFile = config.PrivValKeyFile
			}

			cfg = signer.Config{
				Mode:              "mpc",
				PrivValKeyFile:    privValKeyFile,
				PrivValStateDir:   path.Join(config.HomeDir, "state"),
				ChainID:           config.ChainID,
				CosignerThreshold: config.CosignerConfig.Threshold,
				ListenAddress:     config.CosignerConfig.P2PListen,
				Nodes:             config.Nodes(),
				Cosigners:         config.CosignerPeers(),
			}

			if err = cfg.KeyFileExists(); err != nil {
				return err
			}

			logger.Info("Tendermint Validator", "mode", cfg.Mode,
				"priv-key", cfg.PrivValKeyFile, "priv-state-dir", cfg.PrivValStateDir)

			var val types.PrivValidator

			key, err := signer.LoadCosignerKey(cfg.PrivValKeyFile)
			if err != nil {
				return fmt.Errorf("error reading cosigner key: %s", err)
			}

			// ok to auto initialize on disk since the cosigner share is the one that actually
			// protects against double sign - this exists as a cache for the final signature
			stateFile := path.Join(cfg.PrivValStateDir, fmt.Sprintf("%s_priv_validator_state.json", chainID))
			signState, err := signer.LoadOrCreateSignState(stateFile)
			if err != nil {
				panic(err)
			}

			// state for our cosigner share
			// Not automatically initialized on disk to avoid double sign risk
			shareStateFile := path.Join(cfg.PrivValStateDir, fmt.Sprintf("%s_share_sign_state.json", chainID))
			shareSignState, err := signer.LoadSignState(shareStateFile)
			if err != nil {
				panic(err)
			}

			cosigners := []signer.Cosigner{}

			// add ourselves as a peer so localcosigner can handle GetEphSecPart requests
			peers := []signer.CosignerPeer{{
				ID:        key.ID,
				PublicKey: key.RSAKey.PublicKey,
			}}

			for _, cosignerConfig := range cfg.Cosigners {
				cosigner := signer.NewRemoteCosigner(cosignerConfig.ID, cosignerConfig.Address)
				cosigners = append(cosigners, cosigner)

				if cosignerConfig.ID < 1 || cosignerConfig.ID > len(key.CosignerKeys) {
					log.Fatalf("Unexpected cosigner ID %d", cosignerConfig.ID)
				}

				pubKey := key.CosignerKeys[cosignerConfig.ID-1]
				peers = append(peers, signer.CosignerPeer{
					ID:        cosigner.GetID(),
					PublicKey: *pubKey,
				})
			}

			total := len(cfg.Cosigners) + 1
			localCosignerConfig := signer.LocalCosignerConfig{
				CosignerKey: key,
				SignState:   &shareSignState,
				RsaKey:      key.RSAKey,
				Address:     cfg.ListenAddress,
				Peers:       peers,
				Total:       uint8(total),
				Threshold:   uint8(cfg.CosignerThreshold),
			}

			localCosigner := signer.NewLocalCosigner(localCosignerConfig)

			timeout, _ := time.ParseDuration(config.CosignerConfig.Timeout)

			raftDir := path.Join(config.HomeDir, "raft")
			if err := os.MkdirAll(raftDir, 0700); err != nil {
				log.Fatalf("Error creating raft directory: %v\n", err)
			}

			// RAFT node ID is the cosigner ID
			nodeID := fmt.Sprint(key.ID)

			// Start RAFT store listener
			raftStore := signer.NewRaftStore(nodeID,
				raftDir, cfg.ListenAddress, timeout, logger, localCosigner, cosigners)
			if err := raftStore.Start(); err != nil {
				log.Fatalf("Error starting raft store: %v\n", err)
			}
			services = append(services, raftStore)

			val = signer.NewThresholdValidator(&signer.ThresholdValidatorOpt{
				Pubkey:    key.PubKey,
				Threshold: cfg.CosignerThreshold,
				SignState: signState,
				Cosigner:  localCosigner,
				Peers:     cosigners,
				RaftStore: raftStore,
				Logger:    logger,
			})

			raftStore.SetThresholdValidator(val.(*signer.ThresholdValidator))

			pv = &signer.PvGuard{PrivValidator: val}

			pubkey, err := pv.GetPubKey()
			if err != nil {
				log.Fatal(err)
			}
			logger.Info("Signer", "address", pubkey.Address())

			services, err = signer.StartRemoteSigners(services, logger, cfg.ChainID, pv, cfg.Nodes)
			if err != nil {
				panic(err)
			}

			signer.WaitAndTerminate(logger, services)

			return nil
		},
	}

	return cmd
}
