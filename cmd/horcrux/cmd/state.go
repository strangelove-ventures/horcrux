package cmd

import (
	"encoding/base64"
	"fmt"
	"os"
	"path"

	"github.com/mitchellh/go-homedir"
	"github.com/spf13/cobra"
	"github.com/strangelove-ventures/horcrux/signer"
)

func init() {
	pvCmd.AddCommand(showPvCmd())
	pvCmd.AddCommand(resetPvCmd())
	stateCmd.AddCommand(pvCmd)

	shareCmd.AddCommand(showShareCmd())
	shareCmd.AddCommand(resetShareCmd())
	stateCmd.AddCommand(shareCmd)

	rootCmd.AddCommand(stateCmd)
}

var stateCmd = &cobra.Command{
	Use:   "state",
	Short: "Commands to configure the state",
}

var pvCmd = &cobra.Command{
	Use:   "pv",
	Short: "Commands to configure the priv validator state",
}

func showPvCmd() *cobra.Command {
	return &cobra.Command{
		Use:     "show",
		Aliases: []string{"s"},
		Short:   "Show the priv validator state",
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

			stateFilePath := path.Join(stateDir, config.ChainID+"_priv_validator_state.json")
			ss, err := signer.LoadSignState(stateFilePath)
			if err != nil {
				return err
			}

			printSignState(ss)
			return nil
		},
	}
}

func resetPvCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:     "reset",
		Aliases: []string{"r"},
		Short:   "Reset the priv validator state",
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

			h, err := cmd.Flags().GetInt64("height")
			if err != nil {
				return err
			}

			stateFilePath := path.Join(stateDir, config.ChainID+"_priv_validator_state.json")
			ss, err := signer.LoadSignState(stateFilePath)
			if err != nil {
				return err
			}

			ss.Height, ss.Round, ss.Step = h, 0, 0
			ss.EphemeralPublic, ss.Signature, ss.SignBytes = nil, nil, nil
			ss.Save()
			return nil
		},
	}
	cmd.Flags().Int64("height", 0, "set to reset the priv validator state to the specified height")
	return cmd
}

var shareCmd = &cobra.Command{
	Use:   "share",
	Short: "Commands to configure the share sign state",
}

func showShareCmd() *cobra.Command {
	return &cobra.Command{
		Use:     "show",
		Aliases: []string{"s"},
		Short:   "Show the share sign state",
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

			stateFilePath := path.Join(stateDir, config.ChainID+"_share_sign_state.json")
			ss, err := signer.LoadSignState(stateFilePath)
			if err != nil {
				return err
			}

			printSignState(ss)
			return nil
		},
	}
}

func resetShareCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:     "reset",
		Aliases: []string{"r"},
		Short:   "Reset the share sign state",
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

			h, err := cmd.Flags().GetInt64("height")
			if err != nil {
				return err
			}

			stateFilePath := path.Join(stateDir, config.ChainID+"_share_sign_state.json")
			ss, err := signer.LoadSignState(stateFilePath)
			if err != nil {
				return err
			}

			ss.Height, ss.Round, ss.Step = h, 0, 0
			ss.EphemeralPublic, ss.Signature, ss.SignBytes = nil, nil, nil
			ss.Save()
			return nil
		},
	}
	cmd.Flags().Int64("height", 0, "set to reset the share sign state to the specified height")
	return cmd
}

func printSignState(ss signer.SignState) {
	fmt.Printf("Height:    %v\n"+
		"Round:     %v\n"+
		"Step:      %v\n",
		ss.Height, ss.Round, ss.Step)

	if ss.EphemeralPublic != nil {
		encPub := base64.StdEncoding.EncodeToString(ss.EphemeralPublic)
		fmt.Println("Ephemeral Public Key:", encPub)
	}
	if ss.Signature != nil {
		encSig := base64.StdEncoding.EncodeToString(ss.Signature)
		fmt.Println("Signature:", encSig)
	}
	if ss.SignBytes != nil {
		fmt.Println("SignBytes:", ss.SignBytes)
	}
}
