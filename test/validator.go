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
	"github.com/strangelove-ventures/horcrux/pkg/proto"
	interchaintest "github.com/strangelove-ventures/interchaintest/v7"
	"github.com/strangelove-ventures/interchaintest/v7/chain/cosmos"
	"github.com/strangelove-ventures/interchaintest/v7/ibc"
	"github.com/strangelove-ventures/interchaintest/v7/testutil"
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

	debugPort       = "8453"
	debugPortDocker = debugPort + "/tcp"

	signerImage        = "horcrux-test"
	binary             = "horcrux"
	signerImageUidGid  = "2345:2345"
	signerImageHomeDir = "/home/horcrux"
)

// chainWrapper holds the initial configuration for a chain to start from genesis.
type chainWrapper struct {
	chain           *cosmos.CosmosChain
	totalValidators int // total number of validators on chain at genesis
	totalSentries   int // number of additional sentry nodes
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
// 10 block window, 90% signed blocks required, so more than 1 missed block in 10 blocks will slash and jail the validator.
func modifyGenesisStrictUptime(cc ibc.ChainConfig, b []byte) ([]byte, error) {
	return modifyGenesisSlashingUptime(10, 0.9)(cc, b)
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
		signerImageHomeDir, []string{signerPortDocker, debugPortDocker}, startCmd,
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

// enablePrivvalListener enables the privval listener on the given sentry nodes.
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
	require.Zero(t, signingInfo.MissedBlocksCounter)
}

// transferLeadership elects a new raft leader.
func transferLeadership(ctx context.Context, cosigner *cosmos.SidecarProcess) error {
	_, _, err := cosigner.Exec(ctx, []string{binary, "elect", strconv.FormatInt(int64(cosigner.Index+1), 10)}, nil)
	return err
}

// pollForLeader polls for the given cosigner to become the leader.
func pollForLeader(ctx context.Context, t *testing.T, cosigner *cosmos.SidecarProcess, expectedLeader string) error {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			leader, err := getLeader(ctx, cosigner)
			t.Logf("{%s} => current leader: {%s}, expected leader: {%s}", cosigner.Name(), leader, expectedLeader)
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
func getLeader(ctx context.Context, cosigner *cosmos.SidecarProcess) (string, error) {
	ports, err := cosigner.GetHostPorts(ctx, signerPortDocker)
	if err != nil {
		return "", err
	}
	grpcAddress := ports[0]
	conn, err := grpc.Dial(grpcAddress,
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithDefaultCallOptions(grpc.WaitForReady(true)),
	)
	if err != nil {
		return "", fmt.Errorf("dialing failed: %w", err)
	}
	defer conn.Close()

	ctx, cancelFunc := context.WithTimeout(ctx, 10*time.Second)
	defer cancelFunc()

	grpcClient := proto.NewCosignerGRPCClient(conn)

	res, err := grpcClient.GetLeader(ctx, &proto.CosignerGRPCGetLeaderRequest{})
	if err != nil {
		return "", err
	}
	return res.GetLeader(), nil
}
