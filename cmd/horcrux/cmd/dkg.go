package cmd

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/spf13/cobra"
)

const flagID = "id"

// dkgCmd is a cobra command for performing
// a DKG key ceremony as a participating cosigner.
func dkgCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "dkg",
		Args:  cobra.NoArgs,
		Short: `Command to perform DKG key sharding ceremony (no trusted "dealer")`,
		RunE: func(cmd *cobra.Command, args []string) (err error) {
			flags := cmd.Flags()

			id, _ := flags.GetUint8(flagID)
			chainID, _ := flags.GetString(flagChainID)
			threshold, _ := flags.GetUint8(flagThreshold)
			shards, _ := flags.GetUint8(flagShards)

			var errs []error

			if id == 0 {
				errs = append(errs, fmt.Errorf("id must not be zero"))
			}

			if id > shards {
				errs = append(errs, fmt.Errorf("id must not be greater than total shards"))
			}

			if chainID == "" {
				errs = append(errs, fmt.Errorf("chain-id flag must not be empty"))
			}

			if threshold == 0 {
				errs = append(errs, fmt.Errorf("threshold flag must be > 0, <= --shards, and > --shards/2"))
			}

			if shards == 0 {
				errs = append(errs, fmt.Errorf("shards flag must be greater than zero"))
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

			out, _ := cmd.Flags().GetString(flagOutputDir)
			if out != "" {
				if err := os.MkdirAll(out, 0700); err != nil {
					return err
				}
			}

			// silence usage after all input has been validated
			cmd.SilenceUsage = true

			// cosigner, err := keygen.NewCosigner(id, threshold, shards)
			// if err != nil {
			// 	return err
			// }

			// TODO network routine for connecting to other cosigners and progressing through the rounds
			// maybe libp2p, use cosigners from config on same port? this would ensure that after DKG process,
			// networking is established between cosigners.

			filename := filepath.Join(out, fmt.Sprintf("%s_shard.json", chainID))

			// TODO write shard after DKG

			fmt.Fprintf(cmd.OutOrStdout(), "Created Ed25519 Shard %s\n", filename)

			return nil
		},
	}

	addOutputDirFlag(cmd)
	addTotalShardsFlag(cmd)

	f := cmd.Flags()
	f.Uint8(flagThreshold, 0, "threshold number of shards required to successfully sign")
	_ = cmd.MarkFlagRequired(flagThreshold)
	f.Uint8(flagID, 0, "cosigner shard ID as participant in DKG ceremony")
	_ = cmd.MarkFlagRequired(flagID)
	f.String(flagKeyFile, "", "priv_validator_key.json file to shard")
	_ = cmd.MarkFlagRequired(flagKeyFile)
	f.String(flagChainID, "", "key shards will sign for this chain ID")
	_ = cmd.MarkFlagRequired(flagChainID)

	return cmd
}
