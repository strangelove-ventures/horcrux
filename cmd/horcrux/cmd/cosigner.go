package cmd

import (
	"fmt"
	"log"
	"os"
	"path"
	"time"

	"github.com/spf13/cobra"
	"github.com/strangelove-ventures/horcrux/signer"
	tmlog "github.com/tendermint/tendermint/libs/log"
	tmService "github.com/tendermint/tendermint/libs/service"
	"github.com/tendermint/tendermint/types"
)

func init() {
	cosignerCmd.AddCommand(StartCosignerCmd())
	rootCmd.AddCommand(cosignerCmd)
}

var cosignerCmd = &cobra.Command{
	Use:   "cosigner",
	Short: "Threshold mpc signer for TM based nodes",
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

			cfg = signer.Config{
				Mode:              "mpc",
				PrivValKeyFile:    path.Join(config.HomeDir, "share.json"),
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

			logger.Info("Tendermint Validator", "mode", cfg.Mode, "priv-key", cfg.PrivValKeyFile, "priv-state-dir", cfg.PrivValStateDir)

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
			remoteCosigners := []signer.RemoteCosigner{}

			// add ourselves as a peer so localcosigner can handle GetEphSecPart requests
			peers := []signer.CosignerPeer{{
				ID:        key.ID,
				PublicKey: key.RSAKey.PublicKey,
			}}

			for _, cosignerConfig := range cfg.Cosigners {
				cosigner := signer.NewRemoteCosigner(cosignerConfig.ID, cosignerConfig.Address)
				cosigners = append(cosigners, cosigner)
				remoteCosigners = append(remoteCosigners, *cosigner)

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
				Peers:       peers,
				Total:       uint8(total),
				Threshold:   uint8(cfg.CosignerThreshold),
			}

			localCosigner := signer.NewLocalCosigner(localCosignerConfig)

			val = signer.NewThresholdValidator(&signer.ThresholdValidatorOpt{
				Pubkey:    key.PubKey,
				Threshold: cfg.CosignerThreshold,
				SignState: signState,
				Cosigner:  localCosigner,
				Peers:     cosigners,
			})

			timeout, _ := time.ParseDuration(config.CosignerConfig.Timeout)
			rpcServerConfig := signer.CosignerRpcServerConfig{
				Logger:        logger,
				ListenAddress: cfg.ListenAddress,
				Cosigner:      localCosigner,
				Peers:         remoteCosigners,
				Timeout:       timeout,
			}

			rpcServer := signer.NewCosignerRpcServer(&rpcServerConfig)
			rpcServer.Start()
			services = append(services, rpcServer)

			pv = &signer.PvGuard{PrivValidator: val}

			pubkey, err := pv.GetPubKey()
			if err != nil {
				log.Fatal(err)
			}
			logger.Info("Signer", "pubkey", pubkey)

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
