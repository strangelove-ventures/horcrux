package cmd

import (
	"encoding/base64"
	"fmt"
	"os"
	"strconv"

	"github.com/spf13/cobra"
	"github.com/strangelove-ventures/horcrux/signer"
)

func init() {
	stateCmd.AddCommand(showStateCmd())
	stateCmd.AddCommand(setStateCmd())

	rootCmd.AddCommand(stateCmd)
}

var stateCmd = &cobra.Command{
	Use:   "state",
	Short: "Commands to configure the horcrux signer's state",
}

func showStateCmd() *cobra.Command {
	return &cobra.Command{
		Use:          "show",
		Aliases:      []string{"s"},
		Short:        "Show the priv validator and share sign state",
		Args:         cobra.ExactArgs(0),
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			if _, err := os.Stat(config.HomeDir); os.IsNotExist(err) {
				return fmt.Errorf("%s does not exist, initialize config with horcrux config init and try again", config.HomeDir)
			}

			pv, err := signer.LoadSignState(config.privValStateFile(config.Config.ChainID))
			if err != nil {
				return err
			}

			share, err := signer.LoadSignState(config.shareStateFile(config.Config.ChainID))
			if err != nil {
				return err
			}

			fmt.Println("Private Validator State:")
			printSignState(pv)
			fmt.Println("Share Sign State:")
			printSignState(share)
			return nil
		},
	}
}

func setStateCmd() *cobra.Command {
	return &cobra.Command{
		Use:          "set [height]",
		Aliases:      []string{"s"},
		Short:        "Set the height for both the priv validator and the share sign state",
		Args:         cobra.ExactArgs(1),
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			if _, err := os.Stat(config.HomeDir); os.IsNotExist(err) {
				cmd.SilenceUsage = false
				return fmt.Errorf("%s does not exist, initialize config with horcrux config init and try again", config.HomeDir)
			}

			// Resetting the priv_validator_state.json should only be allowed if the
			// signer is not running.
			if err := signer.RequireNotRunning(config.PidFile); err != nil {
				return err
			}

			pv, err := signer.LoadSignState(config.privValStateFile(config.Config.ChainID))
			if err != nil {
				return err
			}

			share, err := signer.LoadSignState(config.shareStateFile(config.Config.ChainID))
			if err != nil {
				return err
			}

			height, err := strconv.ParseInt(args[0], 10, 64)
			if err != nil {
				cmd.SilenceUsage = false
				return err
			}

			pv.EphemeralPublic, share.EphemeralPublic = nil, nil
			signState := signer.SignStateConsensus{
				Height:    height,
				Round:     0,
				Step:      0,
				Signature: nil,
				SignBytes: nil,
			}
			_ = pv.Save(signState, nil)
			_ = share.Save(signState, nil)
			return nil
		},
	}
}

func printSignState(ss signer.SignState) {
	fmt.Printf("  Height:    %v\n"+
		"  Round:     %v\n"+
		"  Step:      %v\n",
		ss.Height, ss.Round, ss.Step)

	if ss.EphemeralPublic != nil {
		fmt.Println("  Ephemeral Public Key:", base64.StdEncoding.EncodeToString(ss.EphemeralPublic))
	}
	if ss.Signature != nil {
		fmt.Println("  Signature:", base64.StdEncoding.EncodeToString(ss.Signature))
	}
	if ss.SignBytes != nil {
		fmt.Println("  SignBytes:", ss.SignBytes)
	}
}
