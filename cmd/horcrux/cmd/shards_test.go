package cmd

import (
	"io"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/cometbft/cometbft/crypto/ed25519"
	"github.com/cometbft/cometbft/privval"
)

const testChainID = "test"

func TestEd25519Shards(t *testing.T) {
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
			name: "valid threshold and shards",
			args: []string{
				"--chain-id", testChainID,
				"--key-file", privValidatorKeyFile,
				"--threshold", "2",
				"--shards", "3",
			},
			expectErr: false,
		},
		{
			name: "valid threshold and shards 2",
			args: []string{
				"--chain-id", testChainID,
				"--key-file", privValidatorKeyFile,
				"--threshold", "3",
				"--shards", "5",
			},
			expectErr: false,
		},
		{
			name: "threshold exactly half of shards",
			args: []string{
				"--chain-id", testChainID,
				"--key-file", privValidatorKeyFile,
				"--threshold", "2",
				"--shards", "4",
			},
			expectErr: true,
		},
		{
			name: "threshold less than half of shards",
			args: []string{
				"--chain-id", testChainID,
				"--key-file", privValidatorKeyFile,
				"--threshold", "1",
				"--shards", "3",
			},
			expectErr: true,
		},
		{
			name: "threshold exceeds shards",
			args: []string{
				"--chain-id", testChainID,
				"--key-file", privValidatorKeyFile,
				"--threshold", "4",
				"--shards", "3",
			},
			expectErr: true,
		},
		{
			name: "non-numeric threshold and shards",
			args: []string{
				"--chain-id", testChainID,
				"--key-file", privValidatorKeyFile,
				"--threshold", "two",
				"--shards", "three",
			},
			expectErr: true,
		},
	}

	for _, tc := range tcs {
		t.Run(tc.name, func(t *testing.T) {
			cmd := rootCmd()
			cmd.SetOutput(io.Discard)
			args := append([]string{"create-ed25519-shards", "--home", tmp, "--out", tmp}, tc.args...)
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

func TestRSAShards(t *testing.T) {
	tmp := t.TempDir()

	tcs := []struct {
		name      string
		args      []string
		expectErr bool
	}{
		{
			name:      "valid shards",
			args:      []string{"--shards", "3"},
			expectErr: false,
		},
		{
			name:      "invalid shards",
			args:      []string{"--shards", "0"},
			expectErr: true,
		},
	}

	for _, tc := range tcs {
		t.Run(tc.name, func(t *testing.T) {
			cmd := rootCmd()
			cmd.SetOutput(io.Discard)
			args := append([]string{"create-rsa-shards", "--home", tmp, "--out", tmp}, tc.args...)
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
