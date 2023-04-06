package cmd

import (
	"io"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/tendermint/tendermint/crypto/ed25519"
	"github.com/tendermint/tendermint/privval"
)

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
			args:      []string{privValidatorKeyFile, "2", "3"},
			expectErr: false,
		},
		{
			name:      "valid threshold and shares 2",
			args:      []string{privValidatorKeyFile, "3", "5"},
			expectErr: false,
		},
		{
			name:      "threshold exactly half of shares",
			args:      []string{privValidatorKeyFile, "2", "4"},
			expectErr: true,
		},
		{
			name:      "threshold less than half of shares",
			args:      []string{privValidatorKeyFile, "1", "3"},
			expectErr: true,
		},
		{
			name:      "threshold exceeds shares",
			args:      []string{privValidatorKeyFile, "4", "3"},
			expectErr: true,
		},
		{
			name:      "non-numeric threshold and shares",
			args:      []string{privValidatorKeyFile, "two", "three"},
			expectErr: true,
		},
	}

	for _, tc := range tcs {
		t.Run(tc.name, func(t *testing.T) {
			cmd := createCosignerSharesCmd()
			cmd.SetOutput(io.Discard)
			cmd.SetArgs(tc.args)
			err := cmd.Execute()
			if tc.expectErr {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
			}
		})
	}
}
