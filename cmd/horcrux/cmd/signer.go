package cmd

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
	"github.com/strangelove-ventures/horcrux/signer"
	tmlog "github.com/tendermint/tendermint/libs/log"
	tmService "github.com/tendermint/tendermint/libs/service"
)

const (
	flagAcceptRisk = "accept-risk"

	singleSignerWarning = `@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
@ WARNING: SINGLE-SIGNER MODE SHOULD NOT BE USED FOR MAINNET! @
@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
Horcrux single-signer mode does not give the level of improved 
key security and fault tolerance that Horcrux MPC/cosigner mode
provides. While it is a simpler deployment configuration, 
single-signer should only be used for experimentation
as it is not officially supported by Strangelove.`
)

func signerCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "signer",
		Short: "Remote tx signer for TM based nodes.",
	}
	cmd.AddCommand(startSignerCmd())

	return cmd
}

func startSignerCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:          "start",
		Short:        "Start single signer process",
		Args:         cobra.NoArgs,
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, args []string) (err error) {
			fmt.Fprintln(cmd.OutOrStdout(), singleSignerWarning)

			acceptRisk, _ := cmd.Flags().GetBool(flagAcceptRisk)
			if !acceptRisk {
				panic(fmt.Errorf("risk not accepted. --accept-risk flag required to run single signer mode"))
			}

			if err = signer.RequireNotRunning(config.PidFile); err != nil {
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

			_, err = config.KeyFileExistsSingleSigner()
			if err != nil {
				return err
			}

			logger.Info("Tendermint Validator", "mode", "single-signer",
				"priv-key", config.Config.PrivValKeyFile, "priv-state-dir", config.StateDir)

			pv := signer.NewSingleSignerValidator(&config)

			pubkey, err := pv.GetPubKey()
			if err != nil {
				return fmt.Errorf("failed to get public key: %w", err)
			}
			logger.Info("Signer", "pubkey", pubkey)

			go EnableDebugAndMetrics(cmd.Context())

			services, err = signer.StartRemoteSigners(services, logger, pv, config.Config.Nodes())
			if err != nil {
				return fmt.Errorf("failed to start remote signer(s): %w", err)
			}

			signer.WaitAndTerminate(logger, services, config.PidFile)

			return nil
		},
	}

	cmd.Flags().Bool(flagAcceptRisk, false, "Single-signer-mode unsupported. Required to accept risk and proceed.")

	return cmd
}
