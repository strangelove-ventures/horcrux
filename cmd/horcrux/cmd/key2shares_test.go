package cmd

import (
	"io"
	"path/filepath"
	"testing"

	"github.com/cometbft/cometbft/crypto/ed25519"
	"github.com/cometbft/cometbft/privval"
	"github.com/stretchr/testify/require"
)

const testChainID = "test"

func TestKey2Shares(t *testing.T) {
	tmp := t.TempDir()

	privValidatorKeyFile := filepath.Join(tmp, "priv_validator_key.json")
	privValidatorStateFile := filepath.Join(tmp, "priv_validator_state.json")
	pv := privval.NewFilePV(ed25519.GenPrivKey(), privValidatorKeyFile, privValidatorStateFile)
	pv.Save()

	tcs := []struct {
		name      string
		args      []string
		expectErr bool
	}{
		{
			name: "valid threshold and shares",
			args: []string{
				"--chain-id", testChainID,
				"--key-file", privValidatorKeyFile,
				"--threshold", "2",
				"--shares", "3",
			},
			expectErr: false,
		},
		{
			name: "valid threshold and shares 2",
			args: []string{
				"--chain-id", testChainID,
				"--key-file", privValidatorKeyFile,
				"--threshold", "3",
				"--shares", "5",
			},
			expectErr: false,
		},
		{
			name: "threshold exactly half of shares",
			args: []string{
				"--chain-id", testChainID,
				"--key-file", privValidatorKeyFile,
				"--threshold", "2",
				"--shares", "4",
			},
			expectErr: true,
		},
		{
			name: "threshold less than half of shares",
			args: []string{
				"--chain-id", testChainID,
				"--key-file", privValidatorKeyFile,
				"--threshold", "1",
				"--shares", "3",
			},
			expectErr: true,
		},
		{
			name: "threshold exceeds shares",
			args: []string{
				"--chain-id", testChainID,
				"--key-file", privValidatorKeyFile,
				"--threshold", "4",
				"--shares", "3",
			},
			expectErr: true,
		},
		{
			name: "non-numeric threshold and shares",
			args: []string{
				"--chain-id", testChainID,
				"--key-file", privValidatorKeyFile,
				"--threshold", "two",
				"--shares", "three",
			},
			expectErr: true,
		},
	}

	for _, tc := range tcs {
		t.Run(tc.name, func(t *testing.T) {

			cmd := rootCmd()
			cmd.SetOutput(io.Discard)
			args := append([]string{"create-ed25519-shares", "--home", tmp, "--out", tmp}, tc.args...)
			cmd.SetArgs(args)
			err := cmd.Execute()
			if tc.expectErr {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
			}
		})
	}
}

func TestRSAShares(t *testing.T) {
	tmp := t.TempDir()

	tcs := []struct {
		name      string
		args      []string
		expectErr bool
	}{
		{
			name:      "valid shares",
			args:      []string{"--shares", "3"},
			expectErr: false,
		},
		{
			name:      "invalid shares",
			args:      []string{"--shares", "0"},
			expectErr: true,
		},
	}

	for _, tc := range tcs {
		t.Run(tc.name, func(t *testing.T) {
			cmd := rootCmd()
			cmd.SetOutput(io.Discard)
			args := append([]string{"create-rsa-shares", "--home", tmp, "--out", tmp}, tc.args...)
			cmd.SetArgs(args)
			err := cmd.Execute()
			if tc.expectErr {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
			}
		})
	}
}
