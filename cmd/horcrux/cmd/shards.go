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
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/spf13/cobra"
	"github.com/strangelove-ventures/horcrux/signer"
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

func addShardsFlag(cmd *cobra.Command) {
	cmd.Flags().Uint8(flagShards, 0, "total key shards")
}

func addShardFlags(cmd *cobra.Command) {
	addShardsFlag(cmd)
	cmd.Flags().Uint8(flagThreshold, 0, "threshold number of shards required to successfully sign")
	cmd.Flags().String(flagKeyFile, "", "priv_validator_key.json file to shard")
	cmd.Flags().String(flagChainID, "", "key shards will sign for this chain ID")
}

// createCosignerEd25519ShardsCmd is a cobra command for creating
// cosigner shards from a full priv validator key.
func createCosignerEd25519ShardsCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "create-ed25519-shards chain-id priv-validator-key-file threshold shards",
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
				errs = append(errs, fmt.Errorf("key-file flag must be provided and non-empty"))
			}

			if chainID == "" {
				errs = append(errs, fmt.Errorf("chain-id flag must be provided and non-empty"))
			}

			if threshold == 0 {
				errs = append(errs, fmt.Errorf("threshold flag must be provided and non-zero"))
			}

			if shards == 0 {
				errs = append(errs, fmt.Errorf("shards flag must be provided and non-zero"))
			}

			if _, err := os.Stat(keyFile); err != nil {
				errs = append(errs, fmt.Errorf("error accessing priv_validator_key file(%s): %w", keyFile, err))
			}

			if threshold > shards {
				errs = append(errs, fmt.Errorf(
					"threshold cannot be greater than total shards, got [threshold](%d) > [shards](%d)",
					threshold, shards,
				))
			}

			if threshold <= shards/2 {
				errs = append(errs, fmt.Errorf("threshold must be greater than total shards "+
					"divided by 2, got [threshold](%d) <= [shards](%d) / 2", threshold, shards))
			}

			if len(errs) > 0 {
				return errors.Join(errs...)
			}

			csKeys, err := signer.CreateCosignerEd25519ShardsFromFile(keyFile, threshold, shards)
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
				filename := filepath.Join(dir, fmt.Sprintf("%s_shard.json", chainID))
				if err = signer.WriteCosignerEd25519ShardFile(c, filename); err != nil {
					return err
				}
				fmt.Fprintf(cmd.OutOrStdout(), "Created Ed25519 Shard %s\n", filename)
			}
			return nil
		},
	}
	addShardFlags(cmd)
	addOutputDirFlag(cmd)
	return cmd
}

// createCosignerRSAShardsCmd is a cobra command for creating cosigner shards from a priv validator
func createCosignerRSAShardsCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "create-rsa-shards shards",
		Args:  cobra.NoArgs,
		Short: "Create cosigner RSA shards",

		RunE: func(cmd *cobra.Command, args []string) (err error) {
			shards, _ := cmd.Flags().GetUint8(flagShards)

			if shards <= 0 {
				return fmt.Errorf("shards must be greater than zero (%d): %w", shards, err)
			}

			csKeys, err := signer.CreateCosignerRSAShards(int(shards))
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
				if err = signer.WriteCosignerRSAShardFile(c, filename); err != nil {
					return err
				}
				fmt.Fprintf(cmd.OutOrStdout(), "Created RSA Shard %s\n", filename)
			}
			return nil
		},
	}
	addShardsFlag(cmd)
	addOutputDirFlag(cmd)
	return cmd
}
