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
	flagShares    = "shares"
	flagKeyFile   = "key-file"
	flagChainID   = "chain-id"
)

func addOutputDirFlag(cmd *cobra.Command) {
	cmd.Flags().StringP(flagOutputDir, "", "", "output directory")
}

func addShareFlag(cmd *cobra.Command) {
	cmd.Flags().Uint8(flagShares, 0, "total key shares")
}

func addShardFlags(cmd *cobra.Command) {
	addShareFlag(cmd)
	cmd.Flags().Uint8(flagThreshold, 0, "threshold number of shares required to successfully sign")
	cmd.Flags().String(flagKeyFile, "", "priv_validator_key.json file to shard")
	cmd.Flags().String(flagChainID, "", "key shards will sign for this chain ID")
}

// CreateCosignerSharesCmd is a cobra command for creating cosigner shares from a priv validator
func createCosignerEd25519SharesCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:     "create-ed25519-shares chain-id priv-validator-key-file threshold shares",
		Aliases: []string{"shard", "shares"},
		Args:    cobra.NoArgs,
		Short:   "Create cosigner Ed25519 shares",
		RunE: func(cmd *cobra.Command, args []string) (err error) {
			flags := cmd.Flags()

			chainID, _ := flags.GetString(flagChainID)
			keyFile, _ := flags.GetString(flagKeyFile)
			threshold, _ := flags.GetUint8(flagThreshold)
			shares, _ := flags.GetUint8(flagShares)

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

			if shares == 0 {
				errs = append(errs, fmt.Errorf("shares flag must be provided and non-zero"))
			}

			if _, err := os.Stat(keyFile); err != nil {
				errs = append(errs, fmt.Errorf("error accessing priv_validator_key file(%s): %w", keyFile, err))
			}

			if threshold > shares {
				errs = append(errs, fmt.Errorf(
					"threshold cannot be greater than total shares, got [threshold](%d) > [shares](%d)",
					threshold, shares,
				))
			}

			if threshold <= shares/2 {
				errs = append(errs, fmt.Errorf("threshold must be greater than total shares "+
					"divided by 2, got [threshold](%d) <= [shares](%d) / 2", threshold, shares))
			}

			if len(errs) > 0 {
				return errors.Join(errs...)
			}

			csKeys, err := signer.CreateCosignerSharesFromFile(keyFile, threshold, shares)
			if err != nil {
				return err
			}

			out, _ := cmd.Flags().GetString(flagOutputDir)
			if err := os.MkdirAll(out, 0700); err != nil {
				return err
			}

			// silence usage after all input has been validated
			cmd.SilenceUsage = true

			for _, c := range csKeys {
				dir, err := createCosignerDirectoryIfNecessary(out, c.ID)
				if err != nil {
					return err
				}
				filename := filepath.Join(dir, fmt.Sprintf("%s_share.json", chainID))
				if err = signer.WriteCosignerShareFile(c, filename); err != nil {
					return err
				}
				fmt.Fprintf(cmd.OutOrStdout(), "Created Ed25519 Share %s\n", filename)
			}
			return nil
		},
	}
	addShardFlags(cmd)
	addOutputDirFlag(cmd)
	return cmd
}

// CreateCosignerSharesCmd is a cobra command for creating cosigner shares from a priv validator
func createCosignerRSASharesCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:     "create-rsa-shares shares",
		Aliases: []string{"shard", "shares"},
		Args:    cobra.NoArgs,
		Short:   "Create cosigner RSA shares",

		RunE: func(cmd *cobra.Command, args []string) (err error) {
			shares, _ := cmd.Flags().GetUint8(flagShares)

			if shares <= 0 {
				return fmt.Errorf("shares must be greater than zero (%d): %w", shares, err)
			}

			csKeys, err := signer.CreateCosignerSharesRSA(int(shares))
			if err != nil {
				return err
			}

			out, _ := cmd.Flags().GetString(flagOutputDir)
			if err := os.MkdirAll(out, 0700); err != nil {
				return err
			}

			// silence usage after all input has been validated
			cmd.SilenceUsage = true

			for _, c := range csKeys {
				dir, err := createCosignerDirectoryIfNecessary(out, c.ID)
				if err != nil {
					return err
				}
				filename := filepath.Join(dir, "rsa_keys.json")
				if err = signer.WriteCosignerShareRSAFile(c, filename); err != nil {
					return err
				}
				fmt.Fprintf(cmd.OutOrStdout(), "Created RSA Share %s\n", filename)
			}
			return nil
		},
	}
	addShareFlag(cmd)
	addOutputDirFlag(cmd)
	return cmd
}
