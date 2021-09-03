package cmd

import (
	"fmt"
	"log"
	"net"
	"os"
	"path"
	"sync"
	"time"

	"github.com/spf13/cobra"
	"github.com/strangelove-ventures/horcrux/signer"
	tmlog "github.com/tendermint/tendermint/libs/log"
	tmOS "github.com/tendermint/tendermint/libs/os"
	tmService "github.com/tendermint/tendermint/libs/service"
	"github.com/tendermint/tendermint/privval"
	"github.com/tendermint/tendermint/types"
)

func init() {
	cosignerCmd.AddCommand(StartCosignerCmd())
	rootCmd.AddCommand(cosignerCmd)
}

var cosignerCmd = &cobra.Command{
	Use:   "cosigner",
	Short: "A brief description of your command",
}

func StartCosignerCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "start",
		Short: "start cosigner process",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) (err error) {
			single, _ := cmd.Flags().GetBool("single")

			if single {
				err = validateSingleSignerConfig(config)
			} else {
				err = validateCosignerConfig(config)
			}

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

			if single {
				cfg = signer.Config{
					Mode:            "single",
					PrivValKeyFile:  path.Join(config.HomeDir, "priv_validator_key.json"),
					PrivValStateDir: path.Join(config.HomeDir, "state"),
					ChainID:         config.ChainID,
					Nodes:           config.Nodes(),
				}
			} else {
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
			}

			if _, err = os.Stat(cfg.PrivValKeyFile); os.IsNotExist(err) {
				return fmt.Errorf("private key share doesn't exist at path(%s)", cfg.PrivValKeyFile)
			}

			logger.Info("Tendermint Validator", "mode", cfg.Mode, "priv-key", cfg.PrivValKeyFile, "priv-state-dir", cfg.PrivValStateDir)

			var val types.PrivValidator
			if single {
				stateFile := path.Join(cfg.PrivValStateDir, fmt.Sprintf("%s_priv_validator_state.json", chainID))

				// TODO either stop creating state file at config init
				// Triple check that this is how we will handle state file and that this behaves as intended
				// if f, err := os.Stat(stateFile); os.IsNotExist(err) || f.Size() == 0 {
				//  	val = privval.LoadFilePVEmptyState(cfg.PrivValKeyFile, stateFile)
				// 	} else {
				//  	val = privval.LoadFilePV(cfg.PrivValKeyFile, stateFile)
				//  }
				val = privval.LoadFilePVEmptyState(cfg.PrivValKeyFile, stateFile)

				pv = &signer.PvGuard{PrivValidator: val}
			} else {
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

				val := signer.NewThresholdValidator(&signer.ThresholdValidatorOpt{
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
			}

			pubkey, err := pv.GetPubKey()
			if err != nil {
				log.Fatal(err)
			}
			logger.Info("Signer", "pubkey", pubkey)

			for _, node := range cfg.Nodes {
				dialer := net.Dialer{Timeout: 30 * time.Second}
				s := signer.NewReconnRemoteSigner(node.Address, logger, cfg.ChainID, pv, dialer)

				err := s.Start()
				if err != nil {
					panic(err)
				}

				services = append(services, s)
			}

			wg := sync.WaitGroup{}
			wg.Add(1)
			tmOS.TrapSignal(logger, func() {
				for _, service := range services {
					err := service.Stop()
					if err != nil {
						panic(err)
					}
				}
				wg.Done()
			})
			wg.Wait()

			return nil
		},
	}

	cmd.Flags().BoolP("single", "s", false, "set to start horcrux as a single signer")
	return cmd
}
