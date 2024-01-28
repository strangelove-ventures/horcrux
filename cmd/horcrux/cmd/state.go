package cmd

import (
	"bufio"
	"encoding/base64"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/strangelove-ventures/horcrux/src/types"

	"github.com/spf13/cobra"

	cometjson "github.com/cometbft/cometbft/libs/json"
	cometlog "github.com/cometbft/cometbft/libs/log"
)

// Snippet Taken from https://raw.githubusercontent.com/cometbft/cometbft/main/privval/file.go
// FilePVLastSignState stores the mutable part of PrivValidator.
type FilePVLastSignState struct {
	Height int64 `json:"height"`
	Round  int32 `json:"round"`
	Step   int8  `json:"step"`
}

func stateCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "state",
		Short: "Commands to configure the horcrux signer's state",
	}

	cmd.AddCommand(showStateCmd())
	cmd.AddCommand(setStateCmd())
	cmd.AddCommand(importStateCmd())

	return cmd
}

func showStateCmd() *cobra.Command {
	return &cobra.Command{
		Use:          "show [chain-id]",
		Aliases:      []string{"s"},
		Short:        "Show the sign state for a specific chain-id",
		Args:         cobra.ExactArgs(1),
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, args []string) error {

			chainID := args[0]

			if _, err := os.Stat(config.HomeDir); os.IsNotExist(err) {
				return fmt.Errorf("%s does not exist, initialize config with horcrux config init and try again", config.HomeDir)
			}

			pv, err := types.LoadSignState(config.PrivValStateFile(chainID))
			if err != nil {
				return err
			}

			cs, err := types.LoadSignState(config.CosignerStateFile(chainID))
			if err != nil {
				return err
			}

			out := cmd.OutOrStdout()
			fmt.Fprintln(out, "Private Validator State:")
			printSignState(out, pv)
			fmt.Fprintln(out, "Share Sign State:")
			printSignState(out, cs)
			return nil
		},
	}
}

func setStateCmd() *cobra.Command {
	return &cobra.Command{
		Use:          "set chain-id height",
		Aliases:      []string{"s"},
		Short:        "Set the height for the sign state of a specific chain-id",
		Args:         cobra.ExactArgs(2),
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			chainID := args[0]

			out := cmd.OutOrStdout()
			logger := cometlog.NewTMLogger(cometlog.NewSyncWriter(out))

			if _, err := os.Stat(config.HomeDir); os.IsNotExist(err) {
				cmd.SilenceUsage = false
				return fmt.Errorf("%s does not exist, initialize config with horcrux config init and try again", config.HomeDir)
			}

			// Resetting the priv_validator_state.json should only be allowed if the
			// signer is not running.
			if err := RequireNotRunning(logger, config.PidFile); err != nil {
				return err
			}

			pv, err := types.LoadOrCreateSignState(config.PrivValStateFile(chainID))
			if err != nil {
				return err
			}

			cs, err := types.LoadOrCreateSignState(config.CosignerStateFile(chainID))
			if err != nil {
				return err
			}

			height, err := strconv.ParseInt(args[1], 10, 64)
			if err != nil {
				cmd.SilenceUsage = false
				return err
			}

			fmt.Fprintf(out, "Setting height %d\n", height)

			pv.NoncePublic, cs.NoncePublic = nil, nil
			signState := types.SignStateConsensus{
				Height:    height,
				Round:     0,
				Step:      0,
				Signature: nil,
				SignBytes: nil,
			}
			err = pv.Save(signState, nil)
			if err != nil {
				fmt.Printf("error saving privval sign state")
				return err
			}
			err = cs.Save(signState, nil)
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
		Use:     "import chain-id",
		Aliases: []string{"i"},
		Short: "Read the old priv_validator_state.json and set the height, round and step" +
			"(good for migrations but NOT shared state update)",
		Args:         cobra.ExactArgs(1),
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			chainID := args[0]

			if _, err := os.Stat(config.HomeDir); os.IsNotExist(err) {
				cmd.SilenceUsage = false
				return fmt.Errorf("%s does not exist, initialize config with horcrux config init and try again", config.HomeDir)
			}

			out := cmd.OutOrStdout()
			logger := cometlog.NewTMLogger(cometlog.NewSyncWriter(out))

			// Resetting the priv_validator_state.json should only be allowed if the
			// signer is not running.
			if err := RequireNotRunning(logger, config.PidFile); err != nil {
				return err
			}

			// Recreate privValStateFile if necessary
			pv, err := types.LoadOrCreateSignState(config.PrivValStateFile(chainID))
			if err != nil {
				return err
			}

			// shareStateFile does not exist during default config init, so create if necessary
			cs, err := types.LoadOrCreateSignState(config.CosignerStateFile(chainID))
			if err != nil {
				return err
			}

			// Allow user to paste in priv_validator_state.json

			fmt.Fprintln(out, "IMPORTANT: Your validator should already be STOPPED.  You must copy the latest state..")
			<-time.After(2 * time.Second)
			fmt.Fprintln(out, "")
			fmt.Fprintln(out, "Paste your old priv_validator_state.json.  Input a blank line after the pasted JSON to continue.")
			fmt.Fprintln(out, "")

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

			err = cometjson.Unmarshal([]byte(finalJSON), &pvState)
			if err != nil {
				fmt.Println("Error parsing priv_validator_state.json")
				return err
			}

			pv.NoncePublic = nil
			signState := types.SignStateConsensus{
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

			err = pv.Save(signState, nil)
			if err != nil {
				fmt.Printf("error saving privval sign state")
				return err
			}
			err = cs.Save(signState, nil)
			if err != nil {
				fmt.Printf("error saving share sign state")
				return err
			}
			fmt.Printf("Update Successful\n")
			return nil
		},
	}
}

func printSignState(out io.Writer, ss *types.SignState) {
	fmt.Fprintf(out, "  Height:    %v\n"+
		"  Round:     %v\n"+
		"  Step:      %v\n",
		ss.Height, ss.Round, ss.Step)

	if ss.NoncePublic != nil {
		fmt.Fprintln(out, "  Nonce Public Key:", base64.StdEncoding.EncodeToString(ss.NoncePublic))
	}
	if ss.Signature != nil {
		fmt.Fprintln(out, "  Signature:", base64.StdEncoding.EncodeToString(ss.Signature))
	}
	if ss.SignBytes != nil {
		fmt.Fprintln(out, "  SignBytes:", ss.SignBytes)
	}
}
