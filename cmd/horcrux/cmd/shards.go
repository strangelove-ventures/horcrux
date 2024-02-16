/*
Copyright © 2021 NAME HERE <EMAIL ADDRESS>

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/
package cmd

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/strangelove-ventures/horcrux/src/cosigner/nodesecurity"
	"github.com/strangelove-ventures/horcrux/src/tss"

	"github.com/spf13/cobra"
)

func createCosignerDirectoryIfNecessary(out string, id int) (string, error) {
	dir := filepath.Join(out, fmt.Sprintf("cosigner_%d", id))
	dirStat, err := os.Stat(dir)
	if err != nil {
		if !os.IsNotExist(err) {
			return "", fmt.Errorf("unexpected error fetching info for cosigner directory: %w", err)
		}
		if err := os.Mkdir(dir, 0700); err != nil {
			return "", fmt.Errorf("failed to make directory for cosigner files: %w", err)
		}
		return dir, nil
	}
	if !dirStat.IsDir() {
		return "", fmt.Errorf("path must be a directory: %s", dir)
	}
	return dir, nil
}

const (
	flagOutputDir = "out"
	flagThreshold = "threshold"
	flagShards    = "shards"
	flagKeyFile   = "key-file"
	flagChainID   = "chain-id"
)

func addOutputDirFlag(cmd *cobra.Command) {
	cmd.Flags().StringP(flagOutputDir, "", "", "output directory")
}

func addTotalShardsFlag(cmd *cobra.Command) {
	cmd.Flags().Uint8(flagShards, 0, "total key shards")
	_ = cmd.MarkFlagRequired(flagShards)
}

// createCosignerEd25519ShardsCmd is a cobra command for creating
// cosigner shards from a full priv validator key.
func createCosignerEd25519ShardsCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "create-ed25519-shards",
		Args:  cobra.NoArgs,
		Short: "Create cosigner Ed25519 shards",
		RunE: func(cmd *cobra.Command, args []string) (err error) {
			flags := cmd.Flags()

			chainID, _ := flags.GetString(flagChainID)
			keyFile, _ := flags.GetString(flagKeyFile)
			threshold, _ := flags.GetUint8(flagThreshold)
			shards, _ := flags.GetUint8(flagShards)

			var errs []error

			if keyFile == "" {
				return fmt.Errorf("key-file flag must not be empty")
			}

			if chainID == "" {
				return fmt.Errorf(
					"chain-id flag must not be empty")
			}

			if threshold == 0 {
				return fmt.Errorf("threshold flag must be > 0, <= --shards, and > --shards/2")
			}

			if shards == 0 {
				return fmt.Errorf("shards flag must be greater than zero")
			}

			if _, err := os.Stat(keyFile); err != nil {
				return fmt.Errorf("error accessing priv_validator_key file(%s): %w", keyFile, err)
			}

			if threshold > shards {
				return fmt.Errorf(
					"threshold cannot be greater than total shards, got [threshold](%d) > [shards](%d)",
					threshold, shards,
				)
			}

			if threshold <= shards/2 {
				return fmt.Errorf("threshold must be greater than total shards "+
					"divided by 2, got [threshold](%d) <= [shards](%d) / 2", threshold, shards)
			}

			if len(errs) > 0 {
				return nil
			}

			csKeys, err := tss.CreatePersistentEd25519ThresholdSignShardsFromFile(keyFile, threshold, shards)
			if err != nil {
				return fmt.Errorf("error creating CreatePersistentEd25519ThresholdSignShardsFromFile (%s): %d, %d, %w", keyFile, threshold, shards, err)
			}

			out, _ := cmd.Flags().GetString(flagOutputDir)
			if out != "" {
				if err := os.MkdirAll(out, 0700); err != nil {
					return err
				}
			}

			// silence usage after all input has been validated
			cmd.SilenceUsage = true

			for _, c := range csKeys {
				dir, err := createCosignerDirectoryIfNecessary(out, c.ID)
				if err != nil {
					return err
				}
				filename := filepath.Join(dir, fmt.Sprintf("%s_shard.json", chainID))
				if err = tss.WriteToFile(c, filename); err != nil {
					return err
				}
				fmt.Fprintf(cmd.OutOrStdout(), "Created Ed25519 Shard %s\n", filename)
			}
			return nil
		},
	}

	addOutputDirFlag(cmd)
	addTotalShardsFlag(cmd)

	f := cmd.Flags()
	f.Uint8(flagThreshold, 0, "threshold number of shards required to successfully sign")
	_ = cmd.MarkFlagRequired(flagThreshold)
	f.String(flagKeyFile, "", "priv_validator_key.json file to shard")
	_ = cmd.MarkFlagRequired(flagKeyFile)
	f.String(flagChainID, "", "key shards will sign for this chain Index")
	_ = cmd.MarkFlagRequired(flagChainID)

	return cmd
}

// createCosignerECIESShardsCmd is a cobra command for creating cosigner-to-cosigner encryption secp256k1 keys.
func createCosignerECIESShardsCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "create-ecies-shards",
		Args:  cobra.NoArgs,
		Short: "Create cosigner ECIES shards",

		RunE: func(cmd *cobra.Command, args []string) (err error) {
			shards, _ := cmd.Flags().GetUint8(flagShards)

			if shards <= 0 {
				return fmt.Errorf("shards must be greater than zero (%d): %w", shards, err)
			}

			csKeys, err := nodesecurity.CreateCosignerECIESShards(int(shards))
			if err != nil {
				return err
			}

			out, _ := cmd.Flags().GetString(flagOutputDir)
			if out != "" {
				if err := os.MkdirAll(out, 0700); err != nil {
					return err
				}
			}

			// silence usage after all input has been validated
			cmd.SilenceUsage = true

			for _, c := range csKeys {
				dir, err := createCosignerDirectoryIfNecessary(out, c.ID)
				if err != nil {
					return err
				}
				filename := filepath.Join(dir, "ecies_keys.json")
				if err = nodesecurity.WriteCosignerECIESShardFile(c, filename); err != nil {
					return err
				}
				fmt.Fprintf(cmd.OutOrStdout(), "Created ECIES Shard %s\n", filename)
			}
			return nil
		},
	}
	addTotalShardsFlag(cmd)
	addOutputDirFlag(cmd)
	return cmd
}

// createCosignerRSAShardsCmd is a cobra command for creating cosigner-to-cosigner encryption RSA keys.
func createCosignerRSAShardsCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "create-rsa-shards",
		Args:  cobra.NoArgs,
		Short: "Create cosigner RSA shards",

		RunE: func(cmd *cobra.Command, args []string) (err error) {
			shards, _ := cmd.Flags().GetUint8(flagShards)

			if shards <= 0 {
				return fmt.Errorf("shards must be greater than zero (%d): %w", shards, err)
			}

			csKeys, err := nodesecurity.CreateCosignerRSAShards(int(shards))
			if err != nil {
				return err
			}

			out, _ := cmd.Flags().GetString(flagOutputDir)
			if out != "" {
				if err := os.MkdirAll(out, 0700); err != nil {
					return err
				}
			}

			// silence usage after all input has been validated
			cmd.SilenceUsage = true

			for _, c := range csKeys {
				dir, err := createCosignerDirectoryIfNecessary(out, c.ID)
				if err != nil {
					return err
				}
				filename := filepath.Join(dir, "rsa_keys.json")
				if err = nodesecurity.WriteCosignerRSAShardFile(c, filename); err != nil {
					return err
				}
				fmt.Fprintf(cmd.OutOrStdout(), "Created RSA Shard %s\n", filename)
			}
			return nil
		},
	}
	addTotalShardsFlag(cmd)
	addOutputDirFlag(cmd)
	return cmd
}
