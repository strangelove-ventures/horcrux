package cmd

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/spf13/cobra"
	"github.com/strangelove-ventures/horcrux/signer"
)

const flagID = "id"

// dkgCmd is a cobra command for performing
// a DKG key ceremony as a participating cosigner.
func dkgCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "dkg",
		Args:  cobra.NoArgs,
		Short: `Perform DKG key sharding ceremony (no trusted "dealer")`,
		RunE: func(cmd *cobra.Command, args []string) (err error) {
			flags := cmd.Flags()

			id, _ := flags.GetUint8(flagID)
			chainID, _ := flags.GetString(flagChainID)
			threshold := config.Config.ThresholdModeConfig.Threshold
			shards := uint8(len(config.Config.ThresholdModeConfig.Cosigners))

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

			keyFile, err := config.KeyFileExistsCosignerRSA()
			if err != nil {
				return err
			}

			key, err := signer.LoadCosignerRSAKey(keyFile)
			if err != nil {
				return fmt.Errorf("error reading cosigner key (%s): %w", keyFile, err)
			}

			// silence usage after all input has been validated
			cmd.SilenceUsage = true

			shard, err := signer.NetworkDKG(cmd.Context(), config.Config.ThresholdModeConfig.Cosigners, id, key, threshold)
			if err != nil {
				return err
			}

			shardBz, err := shard.MarshalJSON()
			if err != nil {
				return err
			}

			out := config.HomeDir

			if config.Config.PrivValKeyDir != nil {
				out = *config.Config.PrivValKeyDir
			}

			filename := filepath.Join(out, fmt.Sprintf("%s_shard.json", chainID))

			if err := os.WriteFile(filename, shardBz, 0600); err != nil {
				return err
			}

			fmt.Fprintf(cmd.OutOrStdout(), "Created Ed25519 Shard %s\n", filename)

			return nil
		},
	}

	f := cmd.Flags()
	f.Uint8(flagID, 0, "cosigner shard ID as participant in DKG ceremony")
	_ = cmd.MarkFlagRequired(flagID)
	f.String(flagChainID, "", "key shards will sign for this chain ID")
	_ = cmd.MarkFlagRequired(flagChainID)

	return cmd
}
