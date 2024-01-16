package cmd

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
	cconfig "github.com/strangelove-ventures/horcrux/src/config"
)

const (
	flagSignMode    = "mode"
	flagNode        = "node"
	flagCosigner    = "cosigner"
	flagDebugAddr   = "debug-addr"
	flagKeyDir      = "key-dir"
	flagRaftTimeout = "raft-timeout"
	flagGRPCTimeout = "grpc-timeout"
	flagOverwrite   = "overwrite"
	flagBare        = "bare"
	flagGRPCAddress = "flagGRPCAddress"
)

func configCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "config",
		Short: "Commands to configure the horcrux signer",
	}

	cmd.AddCommand(initCmd())
	cmd.AddCommand(migrateCmd())

	return cmd
}

func initCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:     "init",
		Aliases: []string{"i"},
		Short:   "initialize configuration file and home directory if one doesn't already exist",
		Long: `initialize configuration file.
for threshold signer mode, --cosigner flags and --threshold flag are required.
		`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) (err error) {
			cmdFlags := cmd.Flags()

			bare, _ := cmdFlags.GetBool(flagBare)
			nodes, _ := cmdFlags.GetStringSlice(flagNode)

			cn, err := cconfig.ChainNodesFromFlag(nodes)
			if err != nil {
				return err
			}

			overwrite, _ := cmdFlags.GetBool(flagOverwrite)

			if _, err := os.Stat(config.ConfigFile); !os.IsNotExist(err) && !overwrite {
				return fmt.Errorf("%s already exists. Provide the -o flag to overwrite the existing config",
					config.ConfigFile)
			}

			var cfg cconfig.Config

			signMode, _ := cmdFlags.GetString(flagSignMode)
			keyDirFlag, _ := cmdFlags.GetString(flagKeyDir)
			var keyDir *string
			if keyDirFlag != "" {
				keyDir = &keyDirFlag
			}
			debugAddr, _ := cmdFlags.GetString(flagDebugAddr)
			grpcAddr, _ := cmdFlags.GetString(flagGRPCAddress)
			if signMode == string(cconfig.SignModeThreshold) {
				// Threshold Mode Config
				cosignersFlag, _ := cmdFlags.GetStringSlice(flagCosigner)
				threshold, _ := cmdFlags.GetInt(flagThreshold)
				raftTimeout, _ := cmdFlags.GetString(flagRaftTimeout)
				grpcTimeout, _ := cmdFlags.GetString(flagGRPCTimeout)
				cosigners, err := cconfig.CosignersFromFlag(cosignersFlag)
				if err != nil {
					return err
				}

				cfg = cconfig.Config{
					SignMode:      cconfig.SignModeThreshold,
					PrivValKeyDir: keyDir,
					ThresholdModeConfig: &cconfig.ThresholdModeConfig{
						Threshold:   threshold,
						Cosigners:   cosigners,
						GRPCTimeout: grpcTimeout,
						RaftTimeout: raftTimeout,
					},
					ChainNodes: cn,
					DebugAddr:  debugAddr,
					GRPCAddr:   grpcAddr,
				}

				if !bare {
					if err = cfg.ValidateThresholdModeConfig(); err != nil {
						return err
					}
				}
			} else {
				// Single Signer Config
				cfg = cconfig.Config{
					SignMode:      cconfig.SignModeSingle,
					PrivValKeyDir: keyDir,
					ChainNodes:    cn,
					DebugAddr:     debugAddr,
				}
				if !bare {
					if err = cfg.ValidateSingleSignerConfig(); err != nil {
						return err
					}
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

	f := cmd.Flags()
	f.StringP(flagSignMode, "m", string(cconfig.SignModeThreshold),
		`sign mode, "threshold" (recommended) or "single" (unsupported). threshold mode requires --cosigner (multiple) and --threshold`, //nolint
	)
	f.StringSliceP(flagNode, "n", []string{}, "chain cosigner in format tcp://{node-addr}:{privval-port} \n"+
		"(e.g. --node tcp://sentry-1:1234 --node tcp://sentry-2:1234 --node tcp://sentry-3:1234 )")

	f.StringSliceP(flagCosigner, "c", []string{},
		`cosigners in format tcp://{cosigner-addr}:{p2p-port}
(e.g. --cosigner tcp://horcrux-1:2222 --cosigner tcp://horcrux-2:2222 --cosigner tcp://horcrux-3:2222)`)

	f.IntP(flagThreshold, "t", 0, "number of shards required for threshold signature")

	f.StringP(
		flagDebugAddr, "d", "",
		"listen address for debug server and prometheus metrics in format localhost:8543",
	)
	f.StringP(flagKeyDir, "k", "", "key directory if other than home directory")
	f.String(flagRaftTimeout, "500ms", "cosigner raft timeout value, \n"+
		"accepts valid duration strings for Go's time.ParseDuration() e.g. 1s, 1000ms, 1.5m")
	f.String(flagGRPCTimeout, "500ms", "cosigner grpc timeout value, \n"+
		"accepts valid duration strings for Go's time.ParseDuration() e.g. 1s, 1000ms, 1.5m")
	f.BoolP(flagOverwrite, "o", false, "overwrite an existing config.yaml")
	f.Bool(
		flagBare,
		false,
		"allows initialization without providing any flags. If flags are provided, will not perform final validation",
	)
	f.StringP(flagGRPCAddress, "g", "", "GRPC address if listener should be enabled")
	return cmd
}
