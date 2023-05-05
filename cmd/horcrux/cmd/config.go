package cmd

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
	"github.com/strangelove-ventures/horcrux/signer"
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
		Use:     "init [chain-nodes]",
		Aliases: []string{"i"},
		Short:   "initialize configuration file and home directory if one doesn't already exist",
		Long: "initialize configuration file, use flags for cosigner configuration.\n\n" +
			"[chain-nodes] is a comma separated array of chain node addresses i.e.\n" +
			"tcp://chain-node-1:1234,tcp://chain-node-2:1234",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) (err error) {
			cmdFlags := cmd.Flags()

			nodes, _ := cmdFlags.GetStringSlice(flagNode)

			cn, err := signer.ChainNodesFromFlag(nodes)
			if err != nil {
				return err
			}

			overwrite, _ := cmdFlags.GetBool(flagOverwrite)

			if _, err := os.Stat(config.ConfigFile); !os.IsNotExist(err) && !overwrite {
				return fmt.Errorf("%s already exists. Provide the -o flag to overwrite the existing config",
					config.ConfigFile)
			}

			var cfg signer.Config

			signMode, _ := cmdFlags.GetString(flagSignMode)
			keyDirFlag, _ := cmdFlags.GetString(flagKeyDir)
			var keyDir *string
			if keyDirFlag != "" {
				keyDir = &keyDirFlag
			}
			debugAddr, _ := cmdFlags.GetString("debug-addr")
			if signMode == string(signer.SignModeThreshold) {
				// Threshold Mode Config
				cosignersFlag, _ := cmdFlags.GetStringSlice(flagCosigner)
				threshold, _ := cmdFlags.GetInt(flagThreshold)
				raftTimeout, _ := cmdFlags.GetString(flagRaftTimeout)
				grpcTimeout, _ := cmdFlags.GetString(flagGRPCTimeout)
				cosigners, err := signer.CosignersFromFlag(cosignersFlag)
				if err != nil {
					return err
				}

				cfg = signer.Config{
					SignMode:      signer.SignModeThreshold,
					PrivValKeyDir: keyDir,
					ThresholdModeConfig: &signer.ThresholdModeConfig{
						Threshold:   threshold,
						Cosigners:   cosigners,
						GRPCTimeout: grpcTimeout,
						RaftTimeout: raftTimeout,
					},
					ChainNodes: cn,
					DebugAddr:  debugAddr,
				}
				if err = cfg.ValidateThresholdModeConfig(); err != nil {
					return err
				}
			} else {
				// Single Signer Config
				cfg = signer.Config{
					SignMode:      signer.SignModeSingle,
					PrivValKeyDir: keyDir,
					ChainNodes:    cn,
					DebugAddr:     debugAddr,
				}
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
	cmd.Flags().StringP(flagSignMode, "m", string(signer.SignModeThreshold),
		`sign mode, "threshold" (recommended) or "single" (unsupported). threshold mode requires --cosigners and --threshold`,
	)
	cmd.Flags().StringSliceP(flagNode, "n", []string{}, "chain nodes in format tcp://{p2p-addr}:{port}")
	cmd.Flags().StringSliceP(flagCosigner, "c", []string{},
		"cosigners in format tcp://{p2p-addr}:{port}|{shard-id} \n"+
			"(i.e. \"tcp://node-1:2222|1,tcp://node-2:2222|2,tcp://node-3:2222|3\")")
	cmd.Flags().IntP(flagThreshold, "t", 0, "number of shards required for threshold signature")
	cmd.Flags().StringP(
		flagDebugAddr, "d", "",
		"listen address for debug server and prometheus metrics in format localhost:8543",
	)
	cmd.Flags().StringP(flagKeyDir, "k", "", "key directory if other than home directory")
	cmd.Flags().String(flagRaftTimeout, "1500ms", "cosigner raft timeout value, \n"+
		"accepts valid duration strings for Go's time.ParseDuration() e.g. 1s, 1000ms, 1.5m")
	cmd.Flags().String(flagGRPCTimeout, "1500ms", "cosigner grpc timeout value, \n"+
		"accepts valid duration strings for Go's time.ParseDuration() e.g. 1s, 1000ms, 1.5m")
	cmd.Flags().BoolP(flagOverwrite, "o", false, "overwrite an existing config.yaml")
	return cmd
}
