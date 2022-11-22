package cmd

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"
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
	HexAddress        string
	PubKey            string
	ValConsAddress    string
	ValConsPubAddress string
}

func AddressCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:          "address [bech32]",
		Short:        "Get public key hex address and valcons address",
		Example:      `horcrux cosigner address cosmos`,
		SilenceUsage: true,
		Args:         cobra.RangeArgs(0, 1),
		RunE: func(cmd *cobra.Command, args []string) (err error) {
			err = config.Config.ValidateCosignerConfig()
			if err != nil {
				return
			}

			key, err := signer.LoadCosignerKey(*config.Config.PrivValKeyFile)
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

			if len(args) == 1 {
				bech32ValConsAddress, err := bech32.ConvertAndEncode(args[0]+"valcons", pubKeyAddress)
				if err != nil {
					return err
				}
				output.ValConsAddress = bech32ValConsAddress
				pubKeyBech32, err := signer.PubKey(args[0], pubKey)
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

func StartCosignerCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:          "start",
		Short:        "Start cosigner process",
		Args:         cobra.NoArgs,
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := signer.RequireNotRunning(config.PidFile); err != nil {
				return err
			}

			if err := config.Config.ValidateCosignerConfig(); err != nil {
				return err
			}

			var (
				// services to stop on shutdown
				services []tmService.Service
				pv       types.PrivValidator
				logger   = tmlog.NewTMLogger(tmlog.NewSyncWriter(os.Stdout)).With("module", "validator")
			)

			if err := config.KeyFileExists(true); err != nil {
				return err
			}

			logger.Info("Tendermint Validator", "mode", "threshold",
				"priv-key", config.Config.PrivValKeyFile, "priv-state-dir", config.StateDir)

			var val types.PrivValidator

			key, err := signer.LoadCosignerKey(config.KeyFilePath(true))
			if err != nil {
				return fmt.Errorf("error reading cosigner key: %s", err)
			}

			cosigners := []signer.Cosigner{}

			// add ourselves as a peer so localcosigner can handle GetEphSecPart requests
			peers := []signer.CosignerPeer{{
				ID:        key.ID,
				PublicKey: key.RSAKey.PublicKey,
			}}

			for _, cosignerParams := range config.Config.CosignerPeers() {
				cosigner := signer.NewRemoteCosigner(cosignerParams.ID, cosignerParams.Address)
				cosigners = append(cosigners, cosigner)

				if cosignerParams.ID < 1 || cosignerParams.ID > len(key.CosignerKeys) {
					log.Fatalf("Unexpected cosigner ID %d", cosignerParams.ID)
				}

				pubKey := key.CosignerKeys[cosignerParams.ID-1]
				peers = append(peers, signer.CosignerPeer{
					ID:        cosigner.GetID(),
					PublicKey: *pubKey,
				})
			}

			cosignerConfig := config.Config.CosignerConfig

			total := len(cosignerConfig.Peers) + 1

			localCosigner := signer.NewLocalCosigner(
				&config,
				key,
				key.RSAKey,
				peers,
				cosignerConfig.P2PListen,
				uint8(total),
				uint8(cosignerConfig.Threshold),
			)

			timeout, err := time.ParseDuration(cosignerConfig.Timeout)
			if err != nil {
				log.Fatalf("Error parsing configured timeout: %s. %v\n", cosignerConfig.Timeout, err)
			}

			raftDir := filepath.Join(config.HomeDir, "raft")
			if err := os.MkdirAll(raftDir, 0700); err != nil {
				log.Fatalf("Error creating raft directory: %v\n", err)
			}

			// RAFT node ID is the cosigner ID
			nodeID := fmt.Sprint(key.ID)

			// Start RAFT store listener
			raftStore := signer.NewRaftStore(nodeID,
				raftDir, cosignerConfig.P2PListen, timeout, logger, localCosigner, cosigners)
			if err := raftStore.Start(); err != nil {
				log.Fatalf("Error starting raft store: %v\n", err)
			}
			services = append(services, raftStore)

			val = signer.NewThresholdValidator(
				&config,
				key.PubKey,
				cosignerConfig.Threshold,
				localCosigner,
				cosigners,
				raftStore,
				logger,
			)

			raftStore.SetThresholdValidator(val.(*signer.ThresholdValidator))

			pv = &signer.PvGuard{PrivValidator: val}

			pubkey, err := pv.GetPubKey()
			if err != nil {
				log.Fatal(err)
			}
			logger.Info("Signer", "address", pubkey.Address())

			go EnableDebugAndMetrics(cmd.Context())

			services, err = signer.StartRemoteSigners(&config, services, logger, pv, config.Config.Nodes())
			if err != nil {
				panic(err)
			}

			signer.WaitAndTerminate(logger, services, config.PidFile)

			return nil
		},
	}

	return cmd
}
