package cmd

import (
	"bufio"
	"encoding/base64"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"github.com/strangelove-ventures/horcrux/signer"

	tmjson "github.com/tendermint/tendermint/libs/json"
)

// Snippet Taken from https://raw.githubusercontent.com/tendermint/tendermint/main/privval/file.go
// FilePVLastSignState stores the mutable part of PrivValidator.
type FilePVLastSignState struct {
	Height int64 `json:"height"`
	Round  int32 `json:"round"`
	Step   int8  `json:"step"`
}

func init() {
	stateCmd.AddCommand(showStateCmd())
	stateCmd.AddCommand(setStateCmd())
	stateCmd.AddCommand(importStateCmd())

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

			fmt.Fprintf(cmd.OutOrStdout(), "Setting height %d\n", height)

			pv.EphemeralPublic, share.EphemeralPublic = nil, nil
			signState := signer.SignStateConsensus{
				Height:    height,
				Round:     0,
				Step:      0,
				Signature: nil,
				SignBytes: nil,
			}
			err = pv.Save(signState, nil, false)
			if err != nil {
				fmt.Printf("error saving privval sign state")
				return err
			}
			err = share.Save(signState, nil, false)
			if err != nil {
				fmt.Printf("error saving share sign state")
				return err
			}
			return nil
		},
	}
}

func importStateCmd() *cobra.Command {
	return &cobra.Command{
		Use:     "import [height]",
		Aliases: []string{"i"},
		Short: "Read the old priv_validator_state.json and set the height, round and step" +
			"(good for migrations but NOT shared state update)",
		Args:         cobra.ExactArgs(0),
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

			// Recreate privValStateFile if necessary
			pv, err := signer.LoadOrCreateSignState(config.privValStateFile(config.Config.ChainID))
			if err != nil {
				return err
			}

			// shareStateFile does not exist during default config init, so create if necessary
			share, err := signer.LoadOrCreateSignState(config.shareStateFile(config.Config.ChainID))
			if err != nil {
				return err
			}

			// Allow user to paste in priv_validator_state.json

			fmt.Println("IMPORTANT: Your validator should already be STOPPED.  You must copy the latest state..")
			<-time.After(2 * time.Second)
			fmt.Println("")
			fmt.Println("Paste your old priv_validator_state.json.  Input a blank line after the pasted JSON to continue.")
			fmt.Println("")

			var textBuffer strings.Builder

			scanner := bufio.NewScanner(os.Stdin)
			for scanner.Scan() {
				if len(scanner.Text()) == 0 {
					break
				}
				textBuffer.WriteString(scanner.Text())
			}
			finalJSON := textBuffer.String()

			pvState := &FilePVLastSignState{}

			err = tmjson.Unmarshal([]byte(finalJSON), &pvState)
			if err != nil {
				fmt.Println("Error parsing priv_validator_state.json")
				return err
			}

			pv.EphemeralPublic = nil
			signState := signer.SignStateConsensus{
				Height:    pvState.Height,
				Round:     int64(pvState.Round),
				Step:      pvState.Step,
				Signature: nil,
				SignBytes: nil,
			}
			fmt.Printf("Saving New Sign State: \n"+
				"  Height:    %v\n"+
				"  Round:     %v\n"+
				"  Step:      %v\n",
				signState.Height, signState.Round, signState.Step)

			err = pv.Save(signState, nil, false)
			if err != nil {
				fmt.Printf("error saving privval sign state")
				return err
			}
			err = share.Save(signState, nil, false)
			if err != nil {
				fmt.Printf("error saving share sign state")
				return err
			}
			fmt.Printf("Update Successful\n")
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
