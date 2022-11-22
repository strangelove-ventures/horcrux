package cmd

import (
	"errors"
	"fmt"
	"net"
	"net/url"
	"os"

	"github.com/spf13/cobra"
	"github.com/strangelove-ventures/horcrux/signer"
)

func init() {
	configCmd.AddCommand(initCmd())
	rootCmd.AddCommand(configCmd)
}

var configCmd = &cobra.Command{
	Use:   "config",
	Short: "Commands to configure the horcrux signer",
}

func initCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:     "init [chain-nodes]",
		Aliases: []string{"i"},
		Short:   "initialize configuration file and home directory if one doesn't already exist",
		Long: "initialize configuration file, use flags for cosigner configuration.\n\n" +
			"[chain-nodes] is a comma separated array of chain node addresses i.e.\n" +
			"tcp://chain-node-1:1234,tcp://chain-node-2:1234",
		Args: cobra.RangeArgs(0, 1),
		RunE: func(cmd *cobra.Command, args []string) (err error) {
			var cn signer.ChainNodes
			if len(args) == 1 {
				cn, err = signer.ChainNodesFromArg(args[0])
				if err != nil {
					return err
				}
			}

			cmdFlags := cmd.Flags()
			overwrite, _ := cmdFlags.GetBool("overwrite")

			if _, err := os.Stat(config.ConfigFile); !os.IsNotExist(err) && !overwrite {
				return fmt.Errorf("%s already exists. Provide the -o flag to overwrite the existing config",
					config.ConfigFile)
			}

			var cfg signer.DiskConfig

			cs, _ := cmdFlags.GetBool("cosigner")
			keyFileFlag, _ := cmdFlags.GetString("keyfile")
			var keyFile *string
			if keyFileFlag != "" {
				keyFile = &keyFileFlag
			}
			debugAddr, _ := cmdFlags.GetString("debug-addr")
			if cs {
				// Cosigner Config
				p, _ := cmdFlags.GetString("peers")
				threshold, _ := cmdFlags.GetInt("threshold")
				timeout, _ := cmdFlags.GetString("timeout")
				peers, err := signer.PeersFromFlag(p)
				if err != nil {
					return err
				}

				listen, _ := cmdFlags.GetString("listen")
				if listen == "" {
					return errors.New("must input at least one node")
				}
				url, err := url.Parse(listen)
				if err != nil {
					return fmt.Errorf("error parsing listen address: %s, %v", listen, err)
				}
				host, _, err := net.SplitHostPort(url.Host)
				if err != nil {
					return err
				}
				if host == "0.0.0.0" {
					return errors.New("host cannot be 0.0.0.0, must be reachable from other peers")
				}

				cfg = signer.DiskConfig{
					PrivValKeyFile: keyFile,
					CosignerConfig: &signer.CosignerConfig{
						Threshold: threshold,
						Shares:    len(peers) + 1,
						P2PListen: listen,
						Peers:     peers,
						Timeout:   timeout,
					},
					ChainNodes: cn,
					DebugAddr:  debugAddr,
				}
				if err = cfg.ValidateCosignerConfig(); err != nil {
					return err
				}
			} else {
				// Single Signer Config
				cfg.ChainNodes = cn

				if err = cfg.ValidateSingleSignerConfig(); err != nil {
					return err
				}
			}

			// silence usage after all input has been validated
			cmd.SilenceUsage = true

			// create all directories up to the state directory
			if err = os.MkdirAll(config.StateDir, 0755); err != nil {
				return err
			}
			// create the config file
			config.Config = cfg
			if err = config.WriteConfigFile(); err != nil {
				return err
			}

			fmt.Printf("Successfully initialized configuration: %s\n", config.ConfigFile)
			return nil
		},
	}
	cmd.Flags().BoolP("cosigner", "c", false, "set to initialize a cosigner node, requires --peers and --threshold")
	cmd.Flags().StringP("peers", "p", "", "cosigner peer addresses in format tcp://{addr}:{port}|{share-id} \n"+
		"(i.e. \"tcp://node-1:2222|2,tcp://node-2:2222|3\")")
	cmd.Flags().IntP("threshold", "t", 0, "indicate number of signatures required for threshold signature")
	cmd.Flags().StringP("listen", "l", "", "listen address of the signer")
	cmd.Flags().StringP("debug-addr", "d", "", "listen address for Debug and Prometheus metrics in format localhost:8543")
	cmd.Flags().StringP("keyfile", "k", "",
		"priv val key file path (full key for single signer, or key share for cosigner)")
	cmd.Flags().String("timeout", "1500ms", "configure cosigner rpc server timeout value, \n"+
		"accepts valid duration strings for Go's time.ParseDuration() e.g. 1s, 1000ms, 1.5m")
	cmd.Flags().BoolP("overwrite", "o", false, "set to overwrite an existing config.yaml")
	return cmd
}
