package cmd

import (
	"io"
	"os"
	"path/filepath"
	"testing"

	"github.com/strangelove-ventures/horcrux/signer"
	"github.com/stretchr/testify/require"
)

const (
	chainID = "horcrux-1"
)

func TestConfigInitCmd(t *testing.T) {
	tmpHome := t.TempDir()
	tcs := []struct {
		name      string
		home      string
		args      []string
		expectErr bool
	}{
		{
			name: "valid init",
			home: tmpHome + "_valid_init",
			args: []string{
				chainID,
				"tcp://10.168.0.1:1234",
				"-c",
				"-p", "tcp://10.168.1.2:2222|2,tcp://10.168.1.3:2222|3",
				"-t", "2",
				"-l", "tcp://10.168.1.1:2222",
				"--timeout", "1500ms",
			},
			expectErr: false,
		},
		{
			name: "invalid chain-nodes",
			home: tmpHome + "_invalid_chain-nodes",
			args: []string{
				chainID,
				"://10.168.0.1:1234", // Missing/malformed protocol scheme
				"-c",
				"-p", "tcp://10.168.1.2:2222|2,tcp://10.168.1.3:2222|3",
				"-t", "2",
				"-l", "tcp://10.168.1.1:2222",
				"--timeout", "1500ms",
			},
			expectErr: true,
		},
		{
			name: "invalid peer-nodes",
			home: tmpHome + "_invalid_peer-nodes",
			args: []string{
				chainID,
				"tcp://10.168.0.1:1234",
				"-c",
				"-p", "tcp://10.168.1.2:2222,tcp://10.168.1.3:2222", // Missing share IDs
				"-t", "2",
				"-l", "tcp://10.168.1.1:2222",
				"--timeout", "1500ms",
			},
			expectErr: true,
		},
	}

	for _, tc := range tcs {
		t.Run(tc.name, func(t *testing.T) {
			tmpConfig := filepath.Join(tc.home, ".horcrux")

			err := os.MkdirAll(tc.home, 0777)
			require.NoError(t, err)

			cmd := rootCmd()
			cmd.SetOutput(io.Discard)
			args := []string{"--home", tmpConfig, "config", "init"}
			args = append(args, tc.args...)
			cmd.SetArgs(args)
			err = cmd.Execute()

			if tc.expectErr {
				require.Error(t, err)
			} else {
				require.NoError(t, err)

				ss, err := signer.LoadSignState(filepath.Join(tmpConfig, "state", chainID+"_priv_validator_state.json"))
				require.NoError(t, err)
				require.Equal(t, int64(0), ss.Height)
				require.Equal(t, int64(0), ss.Round)
				require.Equal(t, int8(0), ss.Step)
				require.Nil(t, ss.EphemeralPublic)
				require.Nil(t, ss.Signature)
				require.Nil(t, ss.SignBytes)

				ss, err = signer.LoadSignState(filepath.Join(tmpConfig, "state", chainID+"_share_sign_state.json"))
				require.NoError(t, err)
				require.Equal(t, int64(0), ss.Height)
				require.Equal(t, int64(0), ss.Round)
				require.Equal(t, int8(0), ss.Step)
				require.Nil(t, ss.EphemeralPublic)
				require.Nil(t, ss.Signature)
				require.Nil(t, ss.SignBytes)
			}
		})
	}
}
