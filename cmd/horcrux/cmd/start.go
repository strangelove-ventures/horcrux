package cmd

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"os"
	"time"

	"github.com/spf13/cobra"
	"github.com/strangelove-ventures/horcrux/v3/signer"
)

func startCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:          "start",
		Short:        "Start horcrux signer process",
		Args:         cobra.NoArgs,
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, _ []string) error {
			out := cmd.OutOrStdout()
			logger := slog.New(slog.NewTextHandler(out, &slog.HandlerOptions{
				Level: slog.LevelDebug,
			}))

			err := signer.RequireNotRunning(logger, config.PidFile)
			if err != nil {
				return err
			}

			if _, err := legacyConfig(); err == nil {
				return fmt.Errorf("this is a legacy config. run `horcrux config migrate` to migrate to the latest format")
			}

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

			ctx, cancel := context.WithCancel(cmd.Context())
			defer cancel()

			var val signer.PrivValidator

			switch config.Config.SignMode {
			case signer.SignModeThreshold:
				val, err = NewThresholdValidator(ctx, logger)
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

			if config.Config.GRPCAddr != "" {
				grpcServer := signer.NewRemoteSignerGRPCServer(logger, val, config.Config.GRPCAddr)

				go grpcServer.Start()
			}

			go EnableDebugAndMetrics(ctx, out)

			for _, node := range config.Config.Nodes() {
				// CometBFT requires a connection within 3 seconds of start or crashes
				// A long timeout such as 30 seconds would cause the sentry to fail in loops
				// Use a short timeout and dial often to connect within 3 second window
				dialer := net.Dialer{Timeout: 2 * time.Second}
				s := signer.NewReconnRemoteSigner(node, logger, val, dialer)

				go s.Start(ctx)
			}

			signer.WaitAndTerminate(logger, cancel, config.PidFile)

			return nil
		},
	}

	cmd.Flags().Bool(flagAcceptRisk, false, "Single-signer-mode unsupported. Required to accept risk and proceed.")

	return cmd
}
