package cmd

import (
	"io"
	"os"
	"testing"

	"github.com/stretchr/testify/require"
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
			t.Setenv("HOME", tc.home)
			err := os.MkdirAll(tc.home, 0777)
			require.NoError(t, err)

			cmd := initCmd()
			cmd.SetOutput(io.Discard)
			cmd.SetArgs(tc.args)
			err = cmd.Execute()

			if tc.expectErr {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
			}
		})
	}
}
