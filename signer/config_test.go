package signer_test

import (
	"fmt"
	"io/fs"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"testing"

	"github.com/strangelove-ventures/horcrux/signer"
	"github.com/stretchr/testify/require"
)

const testChainID = "test"

func TestNodes(t *testing.T) {
	c := signer.Config{
		ChainNodes: signer.ChainNodes{
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
		config    signer.Config
		expectErr error
	}

	testCases := []testCase{
		{
			name: "valid config",
			config: signer.Config{
				ChainNodes: []signer.ChainNode{
					{
						PrivValAddr: "tcp://127.0.0.1:1234",
					},
				},
			},
			expectErr: nil,
		},
		{
			name: "no nodes configured",
			config: signer.Config{
				ChainNodes: nil,
			},
			expectErr: fmt.Errorf("need to have chain-nodes configured for priv-val connection"),
		},
		{
			name: "invalid node address",
			config: signer.Config{
				ChainNodes: []signer.ChainNode{
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

func TestValidateCosignerConfig(t *testing.T) {
	type testCase struct {
		name      string
		config    signer.Config
		expectErr error
	}

	testCases := []testCase{
		{
			name: "valid config",
			config: signer.Config{
				CosignerConfig: &signer.CosignerConfig{
					Threshold: 2,
					Shares:    3,
					Timeout:   "1000ms",
					P2PListen: "tcp://127.0.0.1:2222",
					Peers: signer.CosignerPeersConfig{
						{
							ShareID: 2,
							P2PAddr: "tcp://127.0.0.1:2223",
						},
						{
							ShareID: 3,
							P2PAddr: "tcp://127.0.0.1:2224",
						},
					},
				},
				ChainNodes: []signer.ChainNode{
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
			config: signer.Config{
				ChainNodes: []signer.ChainNode{
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
			config: signer.Config{
				CosignerConfig: &signer.CosignerConfig{
					Threshold: 2,
					Shares:    3,
					Timeout:   "1000ms",
					P2PListen: ":2222",
					Peers: signer.CosignerPeersConfig{
						{
							ShareID: 2,
							P2PAddr: "tcp://127.0.0.1:2223",
						},
						{
							ShareID: 3,
							P2PAddr: "tcp://127.0.0.1:2224",
						},
					},
				},
				ChainNodes: []signer.ChainNode{
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
			expectErr: fmt.Errorf("failed to parse p2p listen address: %w", &url.Error{
				Op:  "parse",
				URL: ":2222",
				Err: fmt.Errorf("missing protocol scheme"),
			}),
		},
		{
			name: "not enough peers",
			config: signer.Config{
				CosignerConfig: &signer.CosignerConfig{
					Threshold: 2,
					Shares:    3,
					Timeout:   "1000ms",
					P2PListen: "tcp://127.0.0.1:2222",
					Peers: signer.CosignerPeersConfig{
						{
							ShareID: 2,
							P2PAddr: "tcp://127.0.0.1:2223",
						},
					},
				},
				ChainNodes: []signer.ChainNode{
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
			expectErr: fmt.Errorf("incorrect number of peers. expected (3 shares - local node = 2 peers)"),
		},
		{
			name: "invalid timeout",
			config: signer.Config{
				CosignerConfig: &signer.CosignerConfig{
					Threshold: 2,
					Shares:    3,
					Timeout:   "1000",
					P2PListen: "tcp://127.0.0.1:2222",
					Peers: signer.CosignerPeersConfig{
						{
							ShareID: 2,
							P2PAddr: "tcp://127.0.0.1:2223",
						},
						{
							ShareID: 3,
							P2PAddr: "tcp://127.0.0.1:2224",
						},
					},
				},
				ChainNodes: []signer.ChainNode{
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
			expectErr: fmt.Errorf("invalid --timeout: %w", fmt.Errorf("time: missing unit in duration \"1000\"")),
		},
		{
			name: "no nodes configured",
			config: signer.Config{
				CosignerConfig: &signer.CosignerConfig{
					Threshold: 2,
					Shares:    3,
					Timeout:   "1000ms",
					P2PListen: "tcp://127.0.0.1:2222",
					Peers: signer.CosignerPeersConfig{
						{
							ShareID: 2,
							P2PAddr: "tcp://127.0.0.1:2223",
						},
						{
							ShareID: 3,
							P2PAddr: "tcp://127.0.0.1:2224",
						},
					},
				},
				ChainNodes: nil,
			},
			expectErr: fmt.Errorf("need to have chain-nodes configured for priv-val connection"),
		},
		{
			name: "invalid node address",
			config: signer.Config{
				CosignerConfig: &signer.CosignerConfig{
					Threshold: 2,
					Shares:    3,
					Timeout:   "1000ms",
					P2PListen: "tcp://127.0.0.1:2222",
					Peers: signer.CosignerPeersConfig{
						{
							ShareID: 2,
							P2PAddr: "tcp://127.0.0.1:2223",
						},
						{
							ShareID: 3,
							P2PAddr: "tcp://127.0.0.1:2224",
						},
					},
				},
				ChainNodes: []signer.ChainNode{
					{
						PrivValAddr: "abc://\\invalid_addr",
					},
				},
			},
			expectErr: &url.Error{Op: "parse", URL: "abc://\\invalid_addr", Err: url.InvalidHostError("\\")},
		},
	}

	for _, tc := range testCases {
		err := tc.config.ValidateCosignerConfig()
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
	c := signer.RuntimeConfig{
		HomeDir: dir,
	}

	require.Equal(t, filepath.Join(dir, fmt.Sprintf("%s_share.json", testChainID)), c.KeyFilePathCosigner(testChainID))
	require.Equal(
		t,
		filepath.Join(dir, fmt.Sprintf("%s_priv_validator_key.json", testChainID)),
		c.KeyFilePathSingleSigner(testChainID),
	)
}

func TestRuntimeConfigPrivValStateFile(t *testing.T) {
	dir := t.TempDir()
	c := signer.RuntimeConfig{
		StateDir: dir,
	}

	require.Equal(t, filepath.Join(dir, "chain-1_priv_validator_state.json"), c.PrivValStateFile("chain-1"))
}

func TestRuntimeConfigShareStateFile(t *testing.T) {
	dir := t.TempDir()
	c := signer.RuntimeConfig{
		StateDir: dir,
	}

	require.Equal(t, filepath.Join(dir, "chain-1_share_sign_state.json"), c.ShareStateFile("chain-1"))
}

func TestRuntimeConfigWriteConfigFile(t *testing.T) {
	dir := t.TempDir()
	configFile := filepath.Join(dir, "config.yaml")
	c := signer.RuntimeConfig{
		ConfigFile: configFile,
		Config: signer.Config{
			CosignerConfig: &signer.CosignerConfig{
				Threshold: 2,
				Shares:    3,
				Timeout:   "1000ms",
				P2PListen: "tcp://127.0.0.1:2222",
				Peers: signer.CosignerPeersConfig{
					{
						ShareID: 2,
						P2PAddr: "tcp://127.0.0.1:2223",
					},
					{
						ShareID: 3,
						P2PAddr: "tcp://127.0.0.1:2224",
					},
				},
			},
			ChainNodes: []signer.ChainNode{
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
	require.Equal(t, `cosigner:
  threshold: 2
  shares: 3
  p2p-listen: tcp://127.0.0.1:2222
  peers:
  - share-id: 2
    p2p-addr: tcp://127.0.0.1:2223
  - share-id: 3
    p2p-addr: tcp://127.0.0.1:2224
  rpc-timeout: 1000ms
chain-nodes:
- priv-val-addr: tcp://127.0.0.1:1234
- priv-val-addr: tcp://127.0.0.1:2345
- priv-val-addr: tcp://127.0.0.1:3456
`, string(configYamlBz))
}

func TestRuntimeConfigKeyFileExists(t *testing.T) {
	dir := t.TempDir()
	c := signer.RuntimeConfig{
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

func TestCosignerConfigLeaderElectMultiAddress(t *testing.T) {
	c := &signer.CosignerConfig{
		Threshold: 2,
		Shares:    3,
		Timeout:   "1000ms",
		P2PListen: "tcp://127.0.0.1:2222",
		Peers: signer.CosignerPeersConfig{
			{
				ShareID: 2,
				P2PAddr: "tcp://127.0.0.1:2223",
			},
			{
				ShareID: 3,
				P2PAddr: "tcp://127.0.0.1:2224",
			},
		},
	}

	multiAddr, err := c.LeaderElectMultiAddress()
	require.NoError(t, err)
	require.Equal(t, "multi:///127.0.0.1:2222,127.0.0.1:2223,127.0.0.1:2224", multiAddr)
}

func TestCosignerPeersConfigValidate(t *testing.T) {
	type testCase struct {
		name      string
		peers     signer.CosignerPeersConfig
		shares    int
		expectErr error
	}
	testCases := []testCase{
		{
			name: "valid config",
			peers: signer.CosignerPeersConfig{
				{
					ShareID: 2,
					P2PAddr: "tcp://127.0.0.1:2223",
				},
				{
					ShareID: 3,
					P2PAddr: "tcp://127.0.0.1:2224",
				},
			},
			shares:    3,
			expectErr: nil,
		},
		{
			name: "too many peers",
			peers: signer.CosignerPeersConfig{
				{
					ShareID: 2,
					P2PAddr: "tcp://127.0.0.1:2223",
				},
				{
					ShareID: 3,
					P2PAddr: "tcp://127.0.0.1:2224",
				},
			},
			shares:    2,
			expectErr: fmt.Errorf("peer ID 3 in args is out of range, must be between 1 and 2, inclusive"),
		},
		{
			name: "too many shares",
			peers: signer.CosignerPeersConfig{
				{
					ShareID: 2,
					P2PAddr: "tcp://127.0.0.1:2223",
				},
				{
					ShareID: 3,
					P2PAddr: "tcp://127.0.0.1:2224",
				},
			},
			shares:    4,
			expectErr: fmt.Errorf("incorrect number of peers. expected (4 shares - local node = 3 peers)"),
		},
		{
			name: "duplicate peer",
			peers: signer.CosignerPeersConfig{
				{
					ShareID: 2,
					P2PAddr: "tcp://127.0.0.1:2223",
				},
				{
					ShareID: 2,
					P2PAddr: "tcp://127.0.0.1:2223",
				},
			},
			shares:    3,
			expectErr: fmt.Errorf("found duplicate share IDs in args: map[2:[tcp://127.0.0.1:2223 tcp://127.0.0.1:2223]]"),
		},
	}

	for _, tc := range testCases {
		err := tc.peers.Validate(tc.shares)
		if tc.expectErr == nil {
			require.NoError(t, err, tc.name)
		} else {
			require.Error(t, err, tc.name)
			require.EqualError(t, err, tc.expectErr.Error(), tc.name)
		}
	}
}

func TestPeersFromFlag(t *testing.T) {
	type testCase struct {
		name      string
		peers     []string
		expectErr error
	}

	testCases := []testCase{
		{
			name:      "valid peers flag",
			peers:     []string{"tcp://127.0.0.1:2222|1", "tcp://127.0.0.1:2223|2"},
			expectErr: nil,
		},
		{
			name:      "missing peer id",
			peers:     []string{"tcp://127.0.0.1:2222|1", "tcp://127.0.0.1:2223"},
			expectErr: fmt.Errorf("invalid peer string tcp://127.0.0.1:2223, expected format: tcp://{addr}:{port}|{share-id}"),
		},
		{
			name:  "invalid peer id",
			peers: []string{"tcp://127.0.0.1:2222|1", "tcp://127.0.0.1:2223|a"},
			expectErr: fmt.Errorf("failed to parse share ID: %w",
				&strconv.NumError{
					Func: "ParseInt",
					Num:  "a",
					Err:  fmt.Errorf("invalid syntax"),
				},
			),
		},
	}

	for _, tc := range testCases {
		_, err := signer.PeersFromFlag(tc.peers)
		if tc.expectErr == nil {
			require.NoError(t, err, tc.name)
		} else {
			require.Error(t, err, tc.name)
			require.EqualError(t, err, tc.expectErr.Error(), tc.name)
		}
	}
}
