package cmd

import (
	"os"

	"github.com/spf13/cobra"
	"github.com/strangelove-ventures/horcrux/signer"
	tmlog "github.com/tendermint/tendermint/libs/log"
	tmService "github.com/tendermint/tendermint/libs/service"
	"github.com/tendermint/tendermint/privval"
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
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := signer.RequireNotRunning(config.PidFile); err != nil {
				return err
			}

			if err := config.Config.ValidateSingleSignerConfig(); err != nil {
				return err
			}

			var (
				// services to stop on shutdown
				services []tmService.Service
				logger   = tmlog.NewTMLogger(tmlog.NewSyncWriter(os.Stdout)).With("module", "validator")
			)

			if err := config.KeyFileExists(false); err != nil {
				return err
			}

			logger.Info("Tendermint Validator", "mode", "single-signer",
				"priv-key", config.Config.PrivValKeyFile, "priv-state-dir", config.StateDir)

			go EnableDebugAndMetrics(cmd.Context())

			pv := &signer.PvGuard{
				PrivValidator: &privval.FilePV{},
			}

			services, err := signer.StartRemoteSigners(&config, services, logger, pv, config.Config.Nodes())
			if err != nil {
				panic(err)
			}

			signer.WaitAndTerminate(logger, services, config.PidFile)

			return nil
		},
	}

	return cmd
}
