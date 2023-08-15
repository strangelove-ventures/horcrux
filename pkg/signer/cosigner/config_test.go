package cosigner

import (
	"fmt"
	"io/fs"
	"net/url"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

const testChainID = "test"
const TestChainID = "test"

func TestNodes(t *testing.T) {
	c := Config{
		ChainNodes: ChainNodes{
			{
				PrivValAddr: "tcp://0.0.0.0:1234",
			},
			{
				PrivValAddr: "tcp://0.0.0.0:5678",
			},
		},
	}

	require.Equal(t, []string{"tcp://0.0.0.0:1234", "tcp://0.0.0.0:5678"}, c.Nodes())
}

func TestValidateSingleSignerConfig(t *testing.T) {
	type testCase struct {
		name      string
		config    Config
		expectErr error
	}

	testCases := []testCase{
		{
			name: "valid config",
			config: Config{
				ChainNodes: []ChainNode{
					{
						PrivValAddr: "tcp://127.0.0.1:1234",
					},
				},
			},
			expectErr: nil,
		},
		{
			name: "no nodes configured",
			config: Config{
				ChainNodes: nil,
			},
			expectErr: fmt.Errorf("need to have chainNodes configured for priv-val connection"),
		},
		{
			name: "invalid node address",
			config: Config{
				ChainNodes: []ChainNode{
					{
						PrivValAddr: "abc://\\invalid_addr",
					},
				},
			},
			expectErr: &url.Error{Op: "parse", URL: "abc://\\invalid_addr", Err: url.InvalidHostError("\\")},
		},
	}

	for _, tc := range testCases {
		err := tc.config.ValidateSingleSignerConfig()
		if tc.expectErr == nil {
			require.NoError(t, err, tc.name)
		} else {
			require.Error(t, err, tc.name)
			require.EqualError(t, err, tc.expectErr.Error(), tc.name)
		}
	}
}

func TestValidateThresholdModeConfig(t *testing.T) {
	type testCase struct {
		name      string
		config    Config
		expectErr error
	}

	testCases := []testCase{
		{
			name: "valid config",
			config: Config{
				ThresholdModeConfig: &ThresholdModeConfig{
					Threshold:   2,
					RaftTimeout: "1000ms",
					GRPCTimeout: "1000ms",
					Cosigners: CosignersConfig{
						{
							ShardID: 1,
							P2PAddr: "tcp://127.0.0.1:2223",
						},
						{
							ShardID: 2,
							P2PAddr: "tcp://127.0.0.1:2223",
						},
						{
							ShardID: 3,
							P2PAddr: "tcp://127.0.0.1:2224",
						},
					},
				},
				ChainNodes: []ChainNode{
					{
						PrivValAddr: "tcp://127.0.0.1:1234",
					},
					{
						PrivValAddr: "tcp://127.0.0.1:2345",
					},
					{
						PrivValAddr: "tcp://127.0.0.1:3456",
					},
				},
			},
			expectErr: nil,
		},
		{
			name: "no cosigner config",
			config: Config{
				ChainNodes: []ChainNode{
					{
						PrivValAddr: "tcp://127.0.0.1:1234",
					},
					{
						PrivValAddr: "tcp://127.0.0.1:2345",
					},
					{
						PrivValAddr: "tcp://127.0.0.1:3456",
					},
				},
			},
			expectErr: fmt.Errorf("cosigner config can't be empty"),
		},
		{
			name: "invalid p2p listen",
			config: Config{
				ThresholdModeConfig: &ThresholdModeConfig{
					Threshold:   2,
					RaftTimeout: "1000ms",
					GRPCTimeout: "1000ms",
					Cosigners: CosignersConfig{
						{
							ShardID: 1,
							P2PAddr: ":2222",
						},
						{
							ShardID: 2,
							P2PAddr: "tcp://127.0.0.1:2223",
						},
						{
							ShardID: 3,
							P2PAddr: "tcp://127.0.0.1:2224",
						},
					},
				},
				ChainNodes: []ChainNode{
					{
						PrivValAddr: "tcp://127.0.0.1:1234",
					},
					{
						PrivValAddr: "tcp://127.0.0.1:2345",
					},
					{
						PrivValAddr: "tcp://127.0.0.1:3456",
					},
				},
			},
			expectErr: fmt.Errorf("failed to parse cosigner (shard ID: 1) p2p address: %w", &url.Error{
				Op:  "parse",
				URL: ":2222",
				Err: fmt.Errorf("missing protocol scheme"),
			}),
		},
		{
			name: "not enough cosigners",
			config: Config{
				ThresholdModeConfig: &ThresholdModeConfig{
					Threshold:   3,
					RaftTimeout: "1000ms",
					GRPCTimeout: "1000ms",
					Cosigners: CosignersConfig{
						{
							ShardID: 1,
							P2PAddr: "tcp://127.0.0.1:2222",
						},
						{
							ShardID: 2,
							P2PAddr: "tcp://127.0.0.1:2223",
						},
					},
				},
				ChainNodes: []ChainNode{
					{
						PrivValAddr: "tcp://127.0.0.1:1234",
					},
					{
						PrivValAddr: "tcp://127.0.0.1:2345",
					},
					{
						PrivValAddr: "tcp://127.0.0.1:3456",
					},
				},
			},
			expectErr: fmt.Errorf("number of shards (2) must be greater or equal to threshold (3)"),
		},
		{
			name: "invalid raft timeout",
			config: Config{
				ThresholdModeConfig: &ThresholdModeConfig{
					Threshold:   2,
					GRPCTimeout: "1000ms",
					RaftTimeout: "1000",
					Cosigners: CosignersConfig{
						{
							ShardID: 1,
							P2PAddr: "tcp://127.0.0.1:2222",
						},
						{
							ShardID: 2,
							P2PAddr: "tcp://127.0.0.1:2223",
						},
						{
							ShardID: 3,
							P2PAddr: "tcp://127.0.0.1:2224",
						},
					},
				},
				ChainNodes: []ChainNode{
					{
						PrivValAddr: "tcp://127.0.0.1:1234",
					},
					{
						PrivValAddr: "tcp://127.0.0.1:2345",
					},
					{
						PrivValAddr: "tcp://127.0.0.1:3456",
					},
				},
			},
			expectErr: fmt.Errorf("invalid raftTimeout: %w", fmt.Errorf("time: missing unit in duration \"1000\"")),
		},
		{
			name: "invalid grpc timeout",
			config: Config{
				ThresholdModeConfig: &ThresholdModeConfig{
					Threshold:   2,
					GRPCTimeout: "1000",
					RaftTimeout: "1000ms",
					Cosigners: CosignersConfig{
						{
							ShardID: 1,
							P2PAddr: "tcp://127.0.0.1:2222",
						},
						{
							ShardID: 2,
							P2PAddr: "tcp://127.0.0.1:2223",
						},
						{
							ShardID: 3,
							P2PAddr: "tcp://127.0.0.1:2224",
						},
					},
				},
				ChainNodes: []ChainNode{
					{
						PrivValAddr: "tcp://127.0.0.1:1234",
					},
					{
						PrivValAddr: "tcp://127.0.0.1:2345",
					},
					{
						PrivValAddr: "tcp://127.0.0.1:3456",
					},
				},
			},
			expectErr: fmt.Errorf("invalid grpcTimeout: %w", fmt.Errorf("time: missing unit in duration \"1000\"")),
		},
		{
			name: "no nodes configured",
			config: Config{
				ThresholdModeConfig: &ThresholdModeConfig{
					Threshold:   2,
					RaftTimeout: "1000ms",
					GRPCTimeout: "1000ms",
					Cosigners: CosignersConfig{
						{
							ShardID: 1,
							P2PAddr: "tcp://127.0.0.1:2222",
						},
						{
							ShardID: 2,
							P2PAddr: "tcp://127.0.0.1:2223",
						},
						{
							ShardID: 3,
							P2PAddr: "tcp://127.0.0.1:2224",
						},
					},
				},
				ChainNodes: nil,
			},
			expectErr: fmt.Errorf("need to have chainNodes configured for priv-val connection"),
		},
		{
			name: "invalid node address",
			config: Config{
				ThresholdModeConfig: &ThresholdModeConfig{
					Threshold:   2,
					RaftTimeout: "1000ms",
					GRPCTimeout: "1000ms",
					Cosigners: CosignersConfig{
						{
							ShardID: 1,
							P2PAddr: "tcp://127.0.0.1:2222",
						},
						{
							ShardID: 2,
							P2PAddr: "tcp://127.0.0.1:2223",
						},
						{
							ShardID: 3,
							P2PAddr: "tcp://127.0.0.1:2224",
						},
					},
				},
				ChainNodes: []ChainNode{
					{
						PrivValAddr: "abc://\\invalid_addr",
					},
				},
			},
			expectErr: &url.Error{Op: "parse", URL: "abc://\\invalid_addr", Err: url.InvalidHostError("\\")},
		},
	}

	for _, tc := range testCases {
		err := tc.config.ValidateThresholdModeConfig()
		if tc.expectErr == nil {
			require.NoError(t, err, tc.name)
		} else {
			require.Error(t, err, tc.name)
			require.EqualError(t, err, tc.expectErr.Error(), tc.name)
		}
	}
}

func TestRuntimeConfigKeyFilePath(t *testing.T) {
	dir := t.TempDir()
	c := RuntimeConfig{
		HomeDir: dir,
	}

	require.Equal(t, filepath.Join(dir, fmt.Sprintf("%s_shard.json", testChainID)), c.KeyFilePathCosigner(testChainID))
	require.Equal(
		t,
		filepath.Join(dir, fmt.Sprintf("%s_priv_validator_key.json", testChainID)),
		c.KeyFilePathSingleSigner(testChainID),
	)
}

func TestRuntimeConfigPrivValStateFile(t *testing.T) {
	dir := t.TempDir()
	c := RuntimeConfig{
		StateDir: dir,
	}

	require.Equal(t, filepath.Join(dir, "chain-1_priv_validator_state.json"), c.PrivValStateFile("chain-1"))
}

func TestRuntimeConfigWriteConfigFile(t *testing.T) {
	dir := t.TempDir()
	configFile := filepath.Join(dir, "config.yaml")
	c := RuntimeConfig{
		ConfigFile: configFile,
		Config: Config{
			SignMode: SignModeThreshold,
			ThresholdModeConfig: &ThresholdModeConfig{
				Threshold:   2,
				RaftTimeout: "1000ms",
				GRPCTimeout: "1000ms",
				Cosigners: CosignersConfig{
					{
						ShardID: 1,
						P2PAddr: "tcp://127.0.0.1:2222",
					},
					{
						ShardID: 2,
						P2PAddr: "tcp://127.0.0.1:2223",
					},
					{
						ShardID: 3,
						P2PAddr: "tcp://127.0.0.1:2224",
					},
				},
			},
			ChainNodes: []ChainNode{
				{
					PrivValAddr: "tcp://127.0.0.1:1234",
				},
				{
					PrivValAddr: "tcp://127.0.0.1:2345",
				},
				{
					PrivValAddr: "tcp://127.0.0.1:3456",
				},
			},
		},
	}

	require.NoError(t, c.WriteConfigFile())
	configYamlBz, err := os.ReadFile(configFile)
	require.NoError(t, err)
	require.Equal(t, `signMode: threshold
thresholdMode:
  threshold: 2
  cosigners:
  - shardID: 1
    p2pAddr: tcp://127.0.0.1:2222
  - shardID: 2
    p2pAddr: tcp://127.0.0.1:2223
  - shardID: 3
    p2pAddr: tcp://127.0.0.1:2224
  grpcTimeout: 1000ms
  raftTimeout: 1000ms
chainNodes:
- privValAddr: tcp://127.0.0.1:1234
- privValAddr: tcp://127.0.0.1:2345
- privValAddr: tcp://127.0.0.1:3456
debugAddr: ""
`, string(configYamlBz))
}

func TestRuntimeConfigKeyFileExists(t *testing.T) {
	dir := t.TempDir()
	c := RuntimeConfig{
		HomeDir: dir,
	}

	// Test cosigner
	keyFile, err := c.KeyFileExistsCosigner(testChainID)
	require.Error(t, err)

	require.Equal(t, fmt.Errorf(
		"file doesn't exist at path (%s): %w",
		keyFile,
		&fs.PathError{
			Op:   "stat",
			Path: keyFile,
			Err:  fmt.Errorf("no such file or directory"),
		},
	).Error(), err.Error())

	err = os.WriteFile(keyFile, []byte{}, 0600)
	require.NoError(t, err)

	_, err = c.KeyFileExistsCosigner(testChainID)
	require.NoError(t, err)

	// Test single signer
	keyFile, err = c.KeyFileExistsSingleSigner(testChainID)
	require.Error(t, err)

	require.Equal(t, fmt.Errorf(
		"file doesn't exist at path (%s): %w",
		keyFile,
		&fs.PathError{
			Op:   "stat",
			Path: keyFile,
			Err:  fmt.Errorf("no such file or directory"),
		},
	).Error(), err.Error())

	err = os.WriteFile(keyFile, []byte{}, 0600)
	require.NoError(t, err)

	_, err = c.KeyFileExistsSingleSigner(testChainID)
	require.NoError(t, err)
}

func TestThresholdModeConfigLeaderElectMultiAddress(t *testing.T) {
	c := &ThresholdModeConfig{
		Threshold:   2,
		RaftTimeout: "1000ms",
		GRPCTimeout: "1000ms",
		Cosigners: CosignersConfig{
			{
				ShardID: 1,
				P2PAddr: "tcp://127.0.0.1:2222",
			},
			{
				ShardID: 2,
				P2PAddr: "tcp://127.0.0.1:2223",
			},
			{
				ShardID: 3,
				P2PAddr: "tcp://127.0.0.1:2224",
			},
		},
	}

	multiAddr, err := c.LeaderElectMultiAddress()
	require.NoError(t, err)
	require.Equal(t, "multi:///127.0.0.1:2222,127.0.0.1:2223,127.0.0.1:2224", multiAddr)
}

func TestCosignerRSAPubKeysConfigValidate(t *testing.T) {
	type testCase struct {
		name      string
		cosigners CosignersConfig
		expectErr error
	}
	testCases := []testCase{
		{
			name: "valid config",
			cosigners: CosignersConfig{
				{
					ShardID: 1,
					P2PAddr: "tcp://127.0.0.1:2222",
				},
				{
					ShardID: 2,
					P2PAddr: "tcp://127.0.0.1:2223",
				},
				{
					ShardID: 3,
					P2PAddr: "tcp://127.0.0.1:2224",
				},
			},
			expectErr: nil,
		},
		{
			name: "too many cosigners",
			cosigners: CosignersConfig{
				{
					ShardID: 2,
					P2PAddr: "tcp://127.0.0.1:2223",
				},
				{
					ShardID: 3,
					P2PAddr: "tcp://127.0.0.1:2224",
				},
			},
			expectErr: fmt.Errorf("cosigner shard ID 3 in args is out of range, must be between 1 and 2, inclusive"),
		},
		{
			name: "duplicate cosigner",
			cosigners: CosignersConfig{
				{
					ShardID: 2,
					P2PAddr: "tcp://127.0.0.1:2223",
				},
				{
					ShardID: 2,
					P2PAddr: "tcp://127.0.0.1:2223",
				},
			},
			expectErr: fmt.Errorf(
				"found duplicate cosigner shard ID(s) in args: map[2:[tcp://127.0.0.1:2223 tcp://127.0.0.1:2223]]",
			),
		},
	}

	for _, tc := range testCases {
		err := tc.cosigners.Validate()
		if tc.expectErr == nil {
			require.NoError(t, err, tc.name)
		} else {
			require.Error(t, err, tc.name)
			require.EqualError(t, err, tc.expectErr.Error(), tc.name)
		}
	}
}

func TestCosignersFromFlag(t *testing.T) {
	type testCase struct {
		name      string
		cosigners []string
		expectErr error
	}

	testCases := []testCase{
		{
			name:      "valid cosigners flag",
			cosigners: []string{"tcp://127.0.0.1:2222", "tcp://127.0.0.1:2223"},
			expectErr: nil,
		},
	}

	for _, tc := range testCases {
		_, err := CosignersFromFlag(tc.cosigners)
		if tc.expectErr == nil {
			require.NoError(t, err, tc.name)
		} else {
			require.Error(t, err, tc.name)
			require.EqualError(t, err, tc.expectErr.Error(), tc.name)
		}
	}
}
