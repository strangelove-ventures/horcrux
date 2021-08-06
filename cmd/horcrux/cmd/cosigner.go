package cmd

import (
	"fmt"
	"github.com/jackzampolin/horcrux/signer"
	"log"
	"net"
	"os"
	"path"
	"sync"
	"time"

	"github.com/spf13/cobra"
	tmlog "github.com/tendermint/tendermint/libs/log"
	tmOS "github.com/tendermint/tendermint/libs/os"
	tmService "github.com/tendermint/tendermint/libs/service"
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
			if err = validateCosignerConfig(config); err != nil {
				return
			}

			fmt.Println(config)
			var (
				// services to stop on shutdown
				services []tmService.Service
				pv       types.PrivValidator
				chainID  = config.ChainID
				logger   = tmlog.NewTMLogger(tmlog.NewSyncWriter(os.Stdout)).With("module", "validator")
				config   = signer.Config{
					Mode:              "mpc",
					PrivValKeyFile:    path.Join(config.HomeDir, "share.json"),
					PrivValStateDir:   path.Join(config.HomeDir, "state"),
					ChainID:           config.ChainID,
					CosignerThreshold: config.CosignerConfig.Threshold,
					ListenAddress:     config.CosignerConfig.P2PListen,
					Nodes:             config.Nodes(),
					Cosigners:         config.CosignerPeers(),
				}
			)

			if _, err = os.Stat(config.PrivValKeyFile); os.IsNotExist(err) {
				return fmt.Errorf("private key share doesn't exist at path(%s)", config.PrivValKeyFile)
			}

			logger.Info("Tendermint Validator", "mode", config.Mode, "priv-key", config.PrivValKeyFile, "priv-state-dir", config.PrivValStateDir)

			key, err := signer.LoadCosignerKey(config.PrivValKeyFile)
			if err != nil {
				return fmt.Errorf("error reading cosigner key: %s", err)
			}

			// ok to auto initialize on disk since the cosigner share is the one that actually
			// protects against double sign - this exists as a cache for the final signature
			stateFile := path.Join(config.PrivValStateDir, fmt.Sprintf("%s_priv_validator_state.json", chainID))
			signState, err := signer.LoadOrCreateSignState(stateFile)
			if err != nil {
				panic(err)
			}

			// state for our cosigner share
			// Not automatically initialized on disk to avoid double sign risk
			shareStateFile := path.Join(config.PrivValStateDir, fmt.Sprintf("%s_share_sign_state.json", chainID))
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

			for _, cosignerConfig := range config.Cosigners {
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

			total := len(config.Cosigners) + 1
			localCosignerConfig := signer.LocalCosignerConfig{
				CosignerKey: key,
				SignState:   &shareSignState,
				RsaKey:      key.RSAKey,
				Peers:       peers,
				Total:       uint8(total),
				Threshold:   uint8(config.CosignerThreshold),
			}

			localCosigner := signer.NewLocalCosigner(localCosignerConfig)

			val := signer.NewThresholdValidator(&signer.ThresholdValidatorOpt{
				Pubkey:    key.PubKey,
				Threshold: config.CosignerThreshold,
				SignState: signState,
				Cosigner:  localCosigner,
				Peers:     cosigners,
			})

			rpcServerConfig := signer.CosignerRpcServerConfig{
				Logger:        logger,
				ListenAddress: config.ListenAddress,
				Cosigner:      localCosigner,
				Peers:         remoteCosigners,
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

			for _, node := range config.Nodes {
				dialer := net.Dialer{Timeout: 30 * time.Second}
				s := signer.NewReconnRemoteSigner(node.Address, logger, config.ChainID, pv, dialer)

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
	return cmd
}
