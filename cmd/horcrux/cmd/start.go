package cmd

import (
	"fmt"
	"os"

	cometlog "github.com/cometbft/cometbft/libs/log"
	"github.com/cometbft/cometbft/libs/service"
	"github.com/spf13/cobra"
	"github.com/strangelove-ventures/horcrux/signer"
)

func startCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:          "start",
		Short:        "Start horcrux signer process",
		Args:         cobra.NoArgs,
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			err := signer.RequireNotRunning(config.PidFile)
			if err != nil {
				return err
			}

			out := cmd.OutOrStdout()

			if _, err := legacyConfig(); err == nil {
				return fmt.Errorf("this is a legacy config. run `horcrux config migrate` to migrate to the latest format")
			}

			logger := cometlog.NewTMLogger(cometlog.NewSyncWriter(out)).With("module", "validator")

			// create all directories up to the state directory
			if err = os.MkdirAll(config.StateDir, 0700); err != nil {
				return err
			}

			logger.Info(
				"Horcrux Validator",
				"mode", config.Config.SignMode,
				"priv-state-dir", config.StateDir,
			)

			acceptRisk, _ := cmd.Flags().GetBool(flagAcceptRisk)

			var val signer.PrivValidator
			var services []service.Service

			switch config.Config.SignMode {
			case signer.SignModeThreshold:
				services, val, err = NewThresholdValidator(logger)
				if err != nil {
					return err
				}
			case signer.SignModeSingle:
				val, err = NewSingleSignerValidator(out, acceptRisk)
				if err != nil {
					return err
				}
			default:
				panic(fmt.Errorf("unexpected sign mode: %s", config.Config.SignMode))
			}

			go EnableDebugAndMetrics(cmd.Context(), out)

			services, err = signer.StartRemoteSigners(services, logger, val, config.Config.Nodes())
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
