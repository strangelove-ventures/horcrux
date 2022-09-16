package cmd

import (
	"log"
	"os"

	"github.com/spf13/cobra"
	"github.com/strangelove-ventures/horcrux/signer"
	tmlog "github.com/tendermint/tendermint/libs/log"
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
	Short: "Remote tx signer for TM based nodes.",
}

func StartSignerCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:          "start",
		Short:        "Start single signer process",
		Args:         cobra.NoArgs,
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, args []string) (err error) {
			if err = signer.RequireNotRunning(config.PidFile); err != nil {
				return err
			}

			err = validateSingleSignerConfig(config.Config)
			if err != nil {
				return err
			}

			var (
				// services to stop on shutdown
				services []tmService.Service
				pv       types.PrivValidator
				chainID  = config.Config.ChainID
				logger   = tmlog.NewTMLogger(tmlog.NewSyncWriter(os.Stdout)).With("module", "validator")
			)

			privValKeyFile := config.keyFilePath(false)
			nodes := config.Config.Nodes()

			if _, err := os.Stat(privValKeyFile); os.IsNotExist(err) {
				return err
			}

			logger.Info("Tendermint Validator", "mode", "single",
				"priv-key", privValKeyFile, "priv-state-dir", config.StateDir)

			pv = &signer.PvGuard{
				PrivValidator: privval.LoadFilePVEmptyState(privValKeyFile, config.privValStateFile(chainID)),
			}

			pubkey, err := pv.GetPubKey()
			if err != nil {
				log.Fatal(err)
			}
			logger.Info("Signer", "pubkey", pubkey)

			services, err = signer.StartRemoteSigners(services, logger, config.Config.ChainID, pv, nodes)
			if err != nil {
				panic(err)
			}

			signer.WaitAndTerminate(logger, services, config.PidFile)

			return nil
		},
	}

	return cmd
}
