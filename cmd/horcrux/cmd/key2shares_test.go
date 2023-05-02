package cmd

import (
	"io"
	"os"
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
			name:      "valid threshold and shares",
			args:      []string{testChainID, privValidatorKeyFile, "2", "3"},
			expectErr: false,
		},
		{
			name:      "valid threshold and shares 2",
			args:      []string{testChainID, privValidatorKeyFile, "3", "5"},
			expectErr: false,
		},
		{
			name:      "threshold exactly half of shares",
			args:      []string{testChainID, privValidatorKeyFile, "2", "4"},
			expectErr: true,
		},
		{
			name:      "threshold less than half of shares",
			args:      []string{testChainID, privValidatorKeyFile, "1", "3"},
			expectErr: true,
		},
		{
			name:      "threshold exceeds shares",
			args:      []string{testChainID, privValidatorKeyFile, "4", "3"},
			expectErr: true,
		},
		{
			name:      "non-numeric threshold and shares",
			args:      []string{testChainID, privValidatorKeyFile, "two", "three"},
			expectErr: true,
		},
	}

	cwd, err := os.Getwd()
	require.NoError(t, err)

	require.NoError(t, os.Chdir(tmp))

	for _, tc := range tcs {
		t.Run(tc.name, func(t *testing.T) {

			cmd := rootCmd()
			cmd.SetOutput(io.Discard)
			args := append([]string{"create-ed25519-shares", "--home", tmp}, tc.args...)
			cmd.SetArgs(args)
			err := cmd.Execute()
			if tc.expectErr {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
			}
		})
	}

	require.NoError(t, os.Chdir(cwd))
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
			args:      []string{"3"},
			expectErr: false,
		},
		{
			name:      "invalid shares",
			args:      []string{"0"},
			expectErr: true,
		},
	}

	cwd, err := os.Getwd()
	require.NoError(t, err)

	require.NoError(t, os.Chdir(tmp))

	for _, tc := range tcs {
		t.Run(tc.name, func(t *testing.T) {
			cmd := rootCmd()
			cmd.SetOutput(io.Discard)
			args := append([]string{"create-rsa-shares", "--home", tmp}, tc.args...)
			cmd.SetArgs(args)
			err := cmd.Execute()
			if tc.expectErr {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
			}
		})
	}

	require.NoError(t, os.Chdir(cwd))
}
