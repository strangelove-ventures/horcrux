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
	"github.com/jackzampolin/horcrux/signer"
	"github.com/tendermint/tendermint/libs/os"
	"strconv"

	"github.com/spf13/cobra"
)

func init() {
	rootCmd.AddCommand(CreateCosignerSharesCmd())
}

// CreateCosignerSharesCmd is a cobra command for creating cosigner shares from a priv validator
func CreateCosignerSharesCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:     "create-shares [priv_validator.json] [shares] [threshold]",
		Aliases: []string{"shard", "shares"},
		Args:    validateCreateCosignerShares,
		Short:   "create  cosigner shares",
		RunE: func(cmd *cobra.Command, args []string) (err error) {
			threshold, _ := strconv.ParseInt(args[1], 10, 64)
			numShares, _ := strconv.ParseInt(args[2], 10, 64)
			csKeys, err := signer.CreateCosignerSharesFromFile(args[0], threshold, numShares)
			if err != nil {
				return err
			}
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

func validateCreateCosignerShares(cmd *cobra.Command, args []string) error {
	if len(args) != 3 {
		return fmt.Errorf("wrong num args exp(3) got(%d)", len(args))
	}
	if !os.FileExists(args[0]) {
		return fmt.Errorf("priv_validator.json file(%s) doesn't exist", args[0])
	}
	if _, err := strconv.ParseInt(args[1], 10, 64); err != nil {
		return fmt.Errorf("shards must be an integer got(%s)", args[1])
	}
	if _, err := strconv.ParseInt(args[2], 10, 64); err != nil {
		return fmt.Errorf("threshold must be an integer got(%s)", args[2])
	}
	return nil
}