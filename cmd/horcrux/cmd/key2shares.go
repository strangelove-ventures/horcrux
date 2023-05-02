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
	"strconv"

	"github.com/spf13/cobra"
	"github.com/strangelove-ventures/horcrux/signer"
)

func createCosignerDirectoryIfNecessary(id int) (string, error) {
	dir := fmt.Sprintf("cosigner_%d", id)
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

// CreateCosignerSharesCmd is a cobra command for creating cosigner shares from a priv validator
func createCosignerSharesCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:     "create-ed25519-shares [chain-id] [priv_validator.json] [threshold] [shares]",
		Aliases: []string{"shard", "shares"},
		Args:    cobra.ExactArgs(4),
		Short:   "Create  cosigner shares",
		RunE: func(cmd *cobra.Command, args []string) (err error) {
			chainID, keyFile, threshold, shares := args[0], args[1], args[2], args[3]

			if _, err := os.Stat(keyFile); err != nil {
				return fmt.Errorf("error accessing priv_validator_key file(%s): %w", keyFile, err)
			}

			t, err := strconv.ParseInt(threshold, 10, 64)
			if err != nil {
				return fmt.Errorf("error parsing threshold (%s): %w", threshold, err)
			}

			n, err := strconv.ParseInt(shares, 10, 64)
			if err != nil {
				return fmt.Errorf("error parsing shares (%s): %w", shares, err)
			}

			if t > n {
				return fmt.Errorf("threshold cannot be greater than total shares, got [threshold](%d) > [shares](%d)", t, n)
			}

			if t <= n/2 {
				return fmt.Errorf("threshold must be greater than total shares "+
					"divided by 2, got [threshold](%d) <= [shares](%d) / 2", t, n)
			}

			csKeys, err := signer.CreateCosignerSharesFromFile(keyFile, t, n)
			if err != nil {
				return err
			}

			// silence usage after all input has been validated
			cmd.SilenceUsage = true

			for _, c := range csKeys {
				dir, err := createCosignerDirectoryIfNecessary(c.ID)
				if err != nil {
					return err
				}
				filename := filepath.Join(dir, fmt.Sprintf("%s_share.json", chainID))
				if err = signer.WriteCosignerShareFile(c, filename); err != nil {
					return err
				}
				fmt.Printf("Created Ed25519 Share %s\n", filename)
			}
			return nil
		},
	}
	return cmd
}

// CreateCosignerSharesCmd is a cobra command for creating cosigner shares from a priv validator
func createCosignerSharesRSACmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:     "create-rsa-shares [shares]",
		Aliases: []string{"shard", "shares"},
		Args:    cobra.ExactArgs(1),
		Short:   "Create  cosigner shares",

		RunE: func(cmd *cobra.Command, args []string) (err error) {
			shares := args[0]
			n, err := strconv.ParseInt(shares, 10, 64)
			if err != nil {
				return fmt.Errorf("error parsing shares (%s): %w", shares, err)
			}

			csKeys, err := signer.CreateCosignerSharesRSA(int(n))
			if err != nil {
				return err
			}

			// silence usage after all input has been validated
			cmd.SilenceUsage = true

			for _, c := range csKeys {
				dir, err := createCosignerDirectoryIfNecessary(c.ID)
				if err != nil {
					return err
				}
				filename := filepath.Join(dir, "rsa_keys.json")
				if err = signer.WriteCosignerShareRSAFile(c, filename); err != nil {
					return err
				}
				fmt.Printf("Created RSA Share %s\n", filename)
			}
			return nil
		},
	}
	return cmd
}
