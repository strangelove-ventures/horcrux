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
	"strconv"

	"github.com/cometbft/cometbft/libs/os"
	"github.com/spf13/cobra"
	"github.com/strangelove-ventures/horcrux/signer"
)

// CreateCosignerSharesCmd is a cobra command for creating cosigner shares from a priv validator
func createCosignerSharesCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:     "create-shares [priv_validator.json] [threshold] [shares]",
		Aliases: []string{"shard", "shares"},
		Args:    validateCreateCosignerShares,
		Short:   "Create  cosigner shares",
		RunE: func(cmd *cobra.Command, args []string) (err error) {
			threshold, shares := args[1], args[2]
			t, err := strconv.ParseInt(threshold, 10, 64)
			if err != nil {
				return fmt.Errorf("error parsing threshold (%s): %w", threshold, err)
			}
			n, err := strconv.ParseInt(shares, 10, 64)
			if err != nil {
				return fmt.Errorf("error parsing shares (%s): %w", shares, err)
			}

			csKeys, err := signer.CreateCosignerSharesFromFile(args[0], t, n)
			if err != nil {
				return err
			}

			// silence usage after all input has been validated
			cmd.SilenceUsage = true

			for _, c := range csKeys {
				if err = signer.WriteCosignerShareFile(c, fmt.Sprintf("private_share_%d.json", c.ID)); err != nil {
					return err
				}
				fmt.Printf("Created Share %d\n", c.ID)
			}
			return nil
		},
	}
	return cmd
}

// CreateCosignerSharesCmd is a cobra command for creating cosigner shares from a priv validator
func createCosignerSharesRSACmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:     "create-shares-rsa [shares]",
		Aliases: []string{"shard", "shares"},
		Args:    cobra.ExactArgs(1),
		Short:   "Create  cosigner shares",

		RunE: func(cmd *cobra.Command, args []string) (err error) {
			shares := args[2]
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
				filename := fmt.Sprintf("cosigner_%d.json", c.ID)
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

func validateCreateCosignerShares(_ *cobra.Command, args []string) error {
	if len(args) != 3 {
		return fmt.Errorf("wrong num args exp(3) got(%d)", len(args))
	}
	if !os.FileExists(args[0]) {
		return fmt.Errorf("priv_validator.json file(%s) doesn't exist", args[0])
	}
	threshold, shares := args[1], args[2]
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
	return nil
}
