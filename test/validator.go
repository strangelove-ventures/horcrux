package test

import (
	"context"
	"encoding/json"
	"fmt"
	"strconv"
	"testing"
	"time"

	cometbytes "github.com/cometbft/cometbft/libs/bytes"
	cometjson "github.com/cometbft/cometbft/libs/json"
	"github.com/cometbft/cometbft/privval"
	"github.com/cosmos/cosmos-sdk/types/bech32"
	slashingtypes "github.com/cosmos/cosmos-sdk/x/slashing/types"
	"github.com/docker/docker/client"
	"github.com/strangelove-ventures/horcrux/proto/strangelove/proto"

	// "github.com/strangelove-ventures/horcrux/src/proto"
	interchaintest "github.com/strangelove-ventures/interchaintest/v8"
	"github.com/strangelove-ventures/interchaintest/v8/chain/cosmos"
	"github.com/strangelove-ventures/interchaintest/v8/ibc"
	"github.com/strangelove-ventures/interchaintest/v8/testutil"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
	"golang.org/x/sync/errgroup"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

const (
	testChain        = "gaia" // ghcr.io/strangelove-ventures/heighliner/gaia
	testChainVersion = "v10.0.2"

	signerPort       = "2222"
	signerPortDocker = signerPort + "/tcp"

	grpcPort       = "5555"
	grpcPortDocker = grpcPort + "/tcp"

	debugPort       = "8453"
	debugPortDocker = debugPort + "/tcp"

	signerImage        = "horcrux-test"
	binary             = "horcrux"
	signerImageUidGid  = "2345:2345"
	signerImageHomeDir = "/home/horcrux"

	horcruxProxyRegistry = "ghcr.io/strangelove-ventures/horcrux-proxy"
	horcruxProxyTag      = "andrew-horcrux_remote_signer_grpc"
)

// chainWrapper holds the initial configuration for a chain to start from genesis.
type chainWrapper struct {
	chain           *cosmos.CosmosChain
	totalValidators int // total number of validators on chain at genesis
	totalSentries   int // number of additional sentry cosigner
	modifyGenesis   func(cc ibc.ChainConfig, b []byte) ([]byte, error)
	preGenesis      func(*chainWrapper) func(ibc.ChainConfig) error
}

// startChains starts the given chains locally within docker composed of containers.
func startChains(
	ctx context.Context,
	t *testing.T,
	logger *zap.Logger,
	client *client.Client,
	network string,
	chains ...*chainWrapper,
) {
	err := BuildHorcruxImage(ctx, client)
	require.NoError(t, err)

	cs := make([]*interchaintest.ChainSpec, len(chains))
	for i, c := range chains {
		var preGenesis func(ibc.ChainConfig) error
		if c.preGenesis != nil {
			preGenesis = c.preGenesis(c)
		}
		cs[i] = &interchaintest.ChainSpec{
			Name:          testChain,
			Version:       testChainVersion,
			NumValidators: &c.totalValidators,
			NumFullNodes:  &c.totalSentries,
			ChainConfig: ibc.ChainConfig{
				ModifyGenesis: c.modifyGenesis,
				PreGenesis:    preGenesis,
				ConfigFileOverrides: map[string]any{
					"config/config.toml": testutil.Toml{
						"consensus": testutil.Toml{
							"timeout_commit":  "1s",
							"timeout_propose": "1s",
						},
					},
				},
			},
		}
	}

	cf := interchaintest.NewBuiltinChainFactory(logger, cs)

	cfChains, err := cf.Chains(t.Name())
	require.NoError(t, err)

	ic := interchaintest.NewInterchain()

	for i, c := range cfChains {
		chain := c.(*cosmos.CosmosChain)
		chains[i].chain = chain
		ic.AddChain(chain)
	}

	err = ic.Build(ctx, nil, interchaintest.InterchainBuildOptions{
		TestName:  t.Name(),
		Client:    client,
		NetworkID: network,
	})
	require.NoError(t, err)

	t.Cleanup(func() {
		_ = ic.Close()
	})
}

// modifyGenesisStrictUptime modifies the genesis file to have a strict uptime slashing window.
// 10 block window, 80% signed blocks required, so more than 2 missed blocks in 10 blocks will slash and jail the validator.
func modifyGenesisStrictUptime(cc ibc.ChainConfig, b []byte) ([]byte, error) {
	return modifyGenesisSlashingUptime(10, 0.8)(cc, b)
}

// modifyGenesisSlashingUptime modifies the genesis slashing period parameters.
func modifyGenesisSlashingUptime(
	signedBlocksWindow uint64,
	minSignedPerWindow float64,
) func(cc ibc.ChainConfig, b []byte) ([]byte, error) {
	return func(cc ibc.ChainConfig, b []byte) ([]byte, error) {
		g := make(map[string]any)
		if err := json.Unmarshal(b, &g); err != nil {
			return nil, fmt.Errorf("failed to unmarshal genesis file: %w", err)
		}

		g["app_state"].(map[string]any)["slashing"].(map[string]any)["params"].(map[string]any)["signed_blocks_window"] = strconv.FormatUint(signedBlocksWindow, 10)
		g["app_state"].(map[string]any)["slashing"].(map[string]any)["params"].(map[string]any)["min_signed_per_window"] = strconv.FormatFloat(minSignedPerWindow, 'f', 18, 64)

		return json.Marshal(g)
	}
}

// horcruxSidecar creates a horcrux sidecar process that will start when the chain starts.
func horcruxSidecar(ctx context.Context, node *cosmos.ChainNode, name string, client *client.Client, network string, startupFlags ...string) (*cosmos.SidecarProcess, error) {
	startCmd := []string{binary, "start"}
	startCmd = append(startCmd, startupFlags...)
	if err := node.NewSidecarProcess(
		ctx, false, name, client, network,
		ibc.DockerImage{Repository: signerImage, Version: "latest", UidGid: signerImageUidGid},
		signerImageHomeDir, []string{signerPortDocker, grpcPortDocker, debugPortDocker}, startCmd,
	); err != nil {
		return nil, err
	}

	return node.Sidecars[len(node.Sidecars)-1], nil
}

// horcruxSidecar creates a horcrux sidecar process that will start when the chain starts.
func horcruxProxySidecar(ctx context.Context, node *cosmos.ChainNode, name string, client *client.Client, network string, startupFlags ...string) (*cosmos.SidecarProcess, error) {
	startCmd := []string{"horcrux-proxy", "start"}
	startCmd = append(startCmd, startupFlags...)
	if err := node.NewSidecarProcess(
		ctx, false, name, client, network,
		ibc.DockerImage{Repository: horcruxProxyRegistry, Version: horcruxProxyTag, UidGid: "100:1000"},
		signerImageHomeDir, nil, startCmd,
	); err != nil {
		return nil, err
	}

	return node.Sidecars[len(node.Sidecars)-1], nil
}

// getPrivvalKey reads the priv_validator_key.json file from the given node.
func getPrivvalKey(ctx context.Context, node *cosmos.ChainNode) (privval.FilePVKey, error) {
	keyBz, err := node.ReadFile(ctx, "config/priv_validator_key.json")
	if err != nil {
		return privval.FilePVKey{}, fmt.Errorf("failed to read priv_validator_key.json: %w", err)
	}

	pvKey := privval.FilePVKey{}
	if err := cometjson.Unmarshal(keyBz, &pvKey); err != nil {
		return privval.FilePVKey{}, fmt.Errorf("failed to unmarshal priv validator key: %w", err)
	}

	return pvKey, nil
}

// enablePrivvalListener enables the privval listener on the given sentry cosigner.
func enablePrivvalListener(
	ctx context.Context,
	logger *zap.Logger,
	sentries cosmos.ChainNodes,
	client *client.Client,
) error {
	configFileOverrides := testutil.Toml{
		"priv_validator_laddr": "tcp://0.0.0.0:1234",
	}

	var eg errgroup.Group
	for _, s := range sentries {
		s := s

		eg.Go(func() error {
			return testutil.ModifyTomlConfigFile(
				ctx,
				logger,
				client,
				s.TestName,
				s.VolumeName,
				"config/config.toml",
				configFileOverrides,
			)
		})
	}
	return eg.Wait()
}

// getValSigningInfo returns the signing info for the given validator from the reference node.
func getValSigningInfo(tn *cosmos.ChainNode, address cometbytes.HexBytes) (*slashingtypes.ValidatorSigningInfo, error) {
	valConsPrefix := fmt.Sprintf("%svalcons", tn.Chain.Config().Bech32Prefix)

	bech32ValConsAddress, err := bech32.ConvertAndEncode(valConsPrefix, address)
	if err != nil {
		return nil, err
	}
	res, err := slashingtypes.NewQueryClient(tn.CliContext()).SigningInfo(context.Background(), &slashingtypes.QuerySigningInfoRequest{
		ConsAddress: bech32ValConsAddress,
	})
	if err != nil {
		return nil, err
	}

	return &res.ValSigningInfo, nil
}

// requireHealthyValidator asserts that the given validator is not tombstoned, not jailed, and has not missed any blocks in the slashing window.
func requireHealthyValidator(t *testing.T, referenceNode *cosmos.ChainNode, validatorAddress cometbytes.HexBytes) {
	signingInfo, err := getValSigningInfo(referenceNode, validatorAddress)
	require.NoError(t, err)

	require.False(t, signingInfo.Tombstoned)
	require.Equal(t, time.Unix(0, 0).UTC(), signingInfo.JailedUntil)
	require.LessOrEqual(t, signingInfo.MissedBlocksCounter, int64(1))
}

// transferLeadership elects a new raft leader.
func transferLeadership(ctx context.Context, cosigner *cosmos.SidecarProcess) error {
	_, _, err := cosigner.Exec(ctx, []string{binary, "elect", strconv.FormatInt(int64(cosigner.Index+1), 10)}, nil)
	return err
}

// pollForLeader polls for the given cosigner to become the leader.
func pollForLeader(ctx context.Context, t *testing.T, cosigner *cosmos.SidecarProcess, expectedLeader int) error {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			leader, err := getLeader(ctx, cosigner)
			t.Logf("{%s} => current leader: {%d}, expected leader: {%d}", cosigner.Name(), leader, expectedLeader)
			if err != nil {
				return fmt.Errorf("failed to get leader from cosigner: %s - %w", cosigner.Name(), err)
			}
			if leader == expectedLeader {
				return nil
			}
		case <-ctx.Done():
			return fmt.Errorf("leader did not match before timeout for cosigner: %s - %w", cosigner.Name(), ctx.Err())
		}
	}
}

// getLeader returns the current raft leader.
func getLeader(ctx context.Context, cosigner *cosmos.SidecarProcess) (int, error) {
	ports, err := cosigner.GetHostPorts(ctx, signerPortDocker)
	if err != nil {
		return -1, err
	}
	grpcAddress := ports[0]
	conn, err := grpc.Dial(grpcAddress,
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithDefaultCallOptions(grpc.WaitForReady(true)),
	)
	if err != nil {
		return -1, fmt.Errorf("dialing failed: %w", err)
	}
	defer conn.Close()

	ctx, cancelFunc := context.WithTimeout(ctx, 10*time.Second)
	defer cancelFunc()

	grpcClient := proto.NewNodeServiceClient(conn)

	res, err := grpcClient.GetLeader(ctx, &proto.GetLeaderRequest{})
	if err != nil {
		return -1, err
	}
	return int(res.GetLeader()), nil
}
