package cmd

import (
	"fmt"

	cometlog "github.com/cometbft/cometbft/libs/log"
	"github.com/spf13/cobra"
	"github.com/strangelove-ventures/horcrux/signer"
	"github.com/strangelove-ventures/horcrux/signer/proxy"
)

const (
	flagListen = "listen"
	flagAll    = "all"
)

func proxyCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "proxy",
		Short: "Commands for running a horcrux proxy",
	}

	cmd.AddCommand(proxyStartCmd())

	return cmd
}

func proxyStartCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:          "start",
		Short:        "Start horcrux-proxy process",
		Args:         cobra.NoArgs,
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			out := cmd.OutOrStdout()

			logger := cometlog.NewTMLogger(cometlog.NewSyncWriter(out)).With("module", "validator")

			logger.Info("Horcrux Proxy")

			addr, _ := cmd.Flags().GetString(flagListen)
			all, _ := cmd.Flags().GetBool(flagAll)

			listener := proxy.NewSignerListenerEndpoint(logger, addr)
			if err := listener.Start(); err != nil {
				return fmt.Errorf("failed to start listener: %w", err)
			}

			sentries := make(map[string]*signer.ReconnRemoteSigner)

			if err := proxy.WatchForChangedSentries(cmd.Context(), logger, listener, sentries, all); err != nil {
				return err
			}

			proxy.WaitAndTerminate(logger, listener, sentries)

			return nil
		},
	}

	cmd.Flags().StringP(flagListen, "l", "tcp://0.0.0.0:1234", "Privval listen address for the proxy")
	cmd.Flags().BoolP(flagAll, "a", false, "Connect to sentries on all nodes")

	return cmd
}
