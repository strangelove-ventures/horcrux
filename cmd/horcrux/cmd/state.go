package cmd

import (
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path"
	"strconv"

	"github.com/mitchellh/go-homedir"
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
		Use:     "show",
		Aliases: []string{"s"},
		Short:   "Show the priv validator and share sign state",
		Args:    cobra.ExactArgs(0),
		RunE: func(cmd *cobra.Command, args []string) error {
			var stateDir string // In root.go we end up with our
			if homeDir != "" {
				stateDir = path.Join(homeDir, "state")
			} else {
				home, _ := homedir.Dir()
				stateDir = path.Join(home, ".horcrux", "state")
			}
			if _, err := os.Stat(homeDir); !os.IsNotExist(err) {
				return fmt.Errorf("%s is not empty, check for existing configuration and clear path before trying again", homeDir)
			}

			filepath := path.Join(stateDir, config.ChainID+"_priv_validator_state.json")
			pv, err := signer.LoadSignState(filepath)
			if err != nil {
				return err
			}

			filepath = path.Join(stateDir, config.ChainID+"_share_sign_state.json")
			share, err := signer.LoadSignState(filepath)
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
		Use:     "set [height]",
		Aliases: []string{"s"},
		Short:   "Set the height for both the priv validator and the share sign state",
		Args:    cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			// Resetting the priv_validator_state.json should only be allowed if the
			// signer is not running.
			if isRunning() {
				return errors.New("cannot modify state while horcrux is running")
			}

			var stateDir string // In root.go we end up with our
			if homeDir != "" {
				stateDir = path.Join(homeDir, "state")
			} else {
				home, _ := homedir.Dir()
				stateDir = path.Join(home, ".horcrux", "state")
			}
			if _, err := os.Stat(homeDir); !os.IsNotExist(err) {
				return fmt.Errorf("%s is not empty, check for existing configuration and clear path before trying again", homeDir)
			}

			filepath := path.Join(stateDir, config.ChainID+"_priv_validator_state.json")
			pv, err := signer.LoadSignState(filepath)
			if err != nil {
				return err
			}

			filepath = path.Join(stateDir, config.ChainID+"_share_sign_state.json")
			share, err := signer.LoadSignState(filepath)
			if err != nil {
				return err
			}

			height, err := strconv.ParseInt(args[0], 10, 64)
			if err != nil {
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

func isRunning() bool {
	pipe := "ps -ax | pgrep horcrux"
	bz, _ := exec.Command("bash", "-c", pipe).Output()
	return len(bz) != 0
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
