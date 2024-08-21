package cmd

import (
	"io"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestConfigInitCmd(t *testing.T) {
	tmpHome := t.TempDir()
	tcs := []struct {
		name         string
		home         string
		args         []string
		expectErr    string
		expectConfig string
	}{
		{
			name: "valid init threshold",
			home: tmpHome + "_valid_init_threshold",
			args: []string{
				"-n", "tcp://10.168.0.1:1234",
				"-n", "tcp://10.168.0.2:1234",
				"-c", "tcp://10.168.1.1:2222",
				"-c", "tcp://10.168.1.2:2222",
				"-c", "tcp://10.168.1.3:2222",
				"-t", "2",
				"--raft-timeout", "500ms",
				"--grpc-timeout", "500ms",
			},
			expectConfig: `signMode: threshold
thresholdMode:
  threshold: 2
  cosigners:
  - shardID: 1
    p2pAddr: tcp://10.168.1.1:2222
  - shardID: 2
    p2pAddr: tcp://10.168.1.2:2222
  - shardID: 3
    p2pAddr: tcp://10.168.1.3:2222
  grpcTimeout: 500ms
  raftTimeout: 500ms
chainNodes:
- privValAddr: tcp://10.168.0.1:1234
- privValAddr: tcp://10.168.0.2:1234
debugAddr: ""
grpcAddr: ""
maxReadSize: 1048576
`,
		},
		{
			name: "valid init single signer",
			home: tmpHome + "_valid_init_single",
			args: []string{
				"-m", "single",
				"-n", "tcp://10.168.0.1:1234",
				"-n", "tcp://10.168.0.2:1234",
			},
			expectConfig: `signMode: single
chainNodes:
- privValAddr: tcp://10.168.0.1:1234
- privValAddr: tcp://10.168.0.2:1234
debugAddr: ""
grpcAddr: ""
maxReadSize: 1048576
`,
		},
		{
			name: "invalid chain-node",
			home: tmpHome + "_invalid_chain-node",
			args: []string{
				"-n", "://10.168.0.1:1234",
				"-n", "tcp://10.168.0.2:1234",
				"-c", "tcp://10.168.1.1:2222",
				"-c", "tcp://10.168.1.2:2222",
				"-c", "tcp://10.168.1.3:2222",
				"-t", "2",
				"--raft-timeout", "500ms",
				"--grpc-timeout", "500ms",
			},
			expectErr: `parse "://10.168.0.1:1234": missing protocol scheme`,
		},
		{
			name: "invalid cosigner node",
			home: tmpHome + "_invalid_cosigner-node",
			args: []string{
				"-n", "tcp://10.168.0.1:1234",
				"-n", "tcp://10.168.0.2:1234",
				"-c", "://10.168.1.1:2222",
				"-c", "tcp://10.168.1.2:2222",
				"-c", "tcp://10.168.1.3:2222",
				"-t", "2",
				"--raft-timeout", "500ms",
				"--grpc-timeout", "500ms",
			},
			expectErr: `failed to parse cosigner (shard ID: 1) p2p address: parse "://10.168.1.1:2222": missing protocol scheme`,
		},
		{
			name: "invalid threshold",
			home: tmpHome + "_invalid_threshold",
			args: []string{
				"-n", "tcp://10.168.0.1:1234",
				"-n", "tcp://10.168.0.2:1234",
				"-c", "tcp://10.168.1.1:2222",
				"-c", "tcp://10.168.1.2:2222",
				"-c", "tcp://10.168.1.3:2222",
				"-t", "1",
				"--raft-timeout", "500ms",
				"--grpc-timeout", "500ms",
			},
			expectErr: "threshold (1) must be greater than number of shards (3) / 2",
		},
		{
			name: "invalid raft timeout",
			home: tmpHome + "_invalid_raft-timeout",
			args: []string{
				"-n", "tcp://10.168.0.1:1234",
				"-n", "tcp://10.168.0.2:1234",
				"-c", "tcp://10.168.1.1:2222",
				"-c", "tcp://10.168.1.2:2222",
				"-c", "tcp://10.168.1.3:2222",
				"-t", "2",
				"--raft-timeout", "1500",
				"--grpc-timeout", "500ms",
			},
			expectErr: `invalid raftTimeout: time: missing unit in duration "1500"`,
		},
		{
			name: "invalid grpc timeout",
			home: tmpHome + "_invalid_grpc-timeout",
			args: []string{
				"-n", "tcp://10.168.0.1:1234",
				"-n", "tcp://10.168.0.2:1234",
				"-c", "tcp://10.168.1.1:2222",
				"-c", "tcp://10.168.1.2:2222",
				"-c", "tcp://10.168.1.3:2222",
				"-t", "2",
				"--raft-timeout", "500ms",
				"--grpc-timeout", "1500",
			},
			expectErr: `invalid grpcTimeout: time: missing unit in duration "1500"`,
		},
	}

	for _, tc := range tcs {
		t.Run(tc.name, func(t *testing.T) {
			tmpConfig := filepath.Join(tc.home, ".horcrux")

			err := os.MkdirAll(tc.home, 0o777)
			require.NoError(t, err)

			cmd := rootCmd()
			cmd.SetOutput(io.Discard)
			args := []string{"--home", tmpConfig, "config", "init"}
			args = append(args, tc.args...)
			cmd.SetArgs(args)
			err = cmd.Execute()

			if tc.expectErr != "" {
				require.Error(t, err)
				require.EqualError(t, err, tc.expectErr)
			} else {
				require.NoError(t, err)

				actualConfig, err := os.ReadFile(filepath.Join(tmpConfig, "config.yaml"))
				require.NoError(t, err)

				require.Equal(t, tc.expectConfig, string(actualConfig))
			}
		})
	}
}
