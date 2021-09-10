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
	signerCmd.AddCommand(StartSignerCmd())
	rootCmd.AddCommand(signerCmd)
}

var signerCmd = &cobra.Command{
	Use:   "signer",
	Short: "Single signer mode for TM remote tx signer.",
}

func StartSignerCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "start",
		Short: "start single signer process",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) (err error) {

			err = validateSingleSignerConfig(config)

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
				Mode:            "single",
				PrivValKeyFile:  path.Join(config.HomeDir, "priv_validator_key.json"),
				PrivValStateDir: path.Join(config.HomeDir, "state"),
				ChainID:         config.ChainID,
				Nodes:           config.Nodes(),
			}

			if _, err = os.Stat(cfg.PrivValKeyFile); os.IsNotExist(err) {
				return fmt.Errorf("private key share doesn't exist at path(%s)", cfg.PrivValKeyFile)
			}

			logger.Info("Tendermint Validator", "mode", cfg.Mode, "priv-key", cfg.PrivValKeyFile, "priv-state-dir", cfg.PrivValStateDir)

			var val types.PrivValidator
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

	return cmd
}
