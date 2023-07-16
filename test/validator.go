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
	"github.com/strangelove-ventures/horcrux/signer/proto"
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

	signerImage = "horcrux-test"
	binary      = "horcrux"
)

type Logger interface {
	Name() string
	Log(...interface{})
	Logf(string, ...interface{})
}

func startChain(
	ctx context.Context,
	t *testing.T,
	logger *zap.Logger,
	client *client.Client,
	network string,
	chain **cosmos.CosmosChain,
	totalValidators int, // total number of validators on chain at genesis
	totalSentries int, // number of additional sentry nodes
	modifyGenesis func(cc ibc.ChainConfig, b []byte) ([]byte, error),
	preGenesis func(ibc.ChainConfig) error,
) {
	nv := totalValidators
	nf := totalSentries

	err := BuildHorcruxImage(ctx, client)
	require.NoError(t, err)

	cf := interchaintest.NewBuiltinChainFactory(logger, []*interchaintest.ChainSpec{
		{
			Name:          testChain,
			Version:       testChainVersion,
			NumValidators: &nv,
			NumFullNodes:  &nf,
			ChainConfig: ibc.ChainConfig{
				ModifyGenesis: modifyGenesis,
				PreGenesis:    preGenesis,
			},
		},
	})

	chains, err := cf.Chains(t.Name())
	require.NoError(t, err)

	*chain = chains[0].(*cosmos.CosmosChain)

	ic := interchaintest.NewInterchain().AddChain(*chain)

	err = ic.Build(ctx, nil, interchaintest.InterchainBuildOptions{
		TestName:  t.Name(),
		Client:    client,
		NetworkID: network,
		// BlockDatabaseFile: interchaintest.DefaultBlockDatabaseFilepath(),
		SkipPathCreation: false,
	})
	require.NoError(t, err)

	t.Cleanup(func() {
		_ = ic.Close()
	})
}

func startTwoChains(
	ctx context.Context,
	t *testing.T,
	logger *zap.Logger,
	client *client.Client,
	network string,
	chain1 **cosmos.CosmosChain,
	chain2 **cosmos.CosmosChain,
	totalValidators int, // total number of validators on chain at genesis
	totalSentries int, // number of additional sentry nodes
	modifyGenesis1 func(cc ibc.ChainConfig, b []byte) ([]byte, error),
	preGenesis1 func(ibc.ChainConfig) error,
	modifyGenesis2 func(cc ibc.ChainConfig, b []byte) ([]byte, error),
	preGenesis2 func(ibc.ChainConfig) error,
) {
	nv := totalValidators
	nf := totalSentries

	err := BuildHorcruxImage(ctx, client)
	require.NoError(t, err)

	cf := interchaintest.NewBuiltinChainFactory(logger, []*interchaintest.ChainSpec{
		{
			Name:          testChain,
			Version:       testChainVersion,
			NumValidators: &nv,
			NumFullNodes:  &nf,
			ChainConfig: ibc.ChainConfig{
				ModifyGenesis: modifyGenesis1,
				PreGenesis:    preGenesis1,
			},
		},
		{
			Name:          testChain,
			Version:       testChainVersion,
			NumValidators: &nv,
			NumFullNodes:  &nf,
			ChainConfig: ibc.ChainConfig{
				ModifyGenesis: modifyGenesis2,
				PreGenesis:    preGenesis2,
			},
		},
	})

	chains, err := cf.Chains(t.Name())
	require.NoError(t, err)

	*chain1, *chain2 = chains[0].(*cosmos.CosmosChain), chains[1].(*cosmos.CosmosChain)

	ic := interchaintest.NewInterchain().AddChain(*chain1).AddChain(*chain2)

	err = ic.Build(ctx, nil, interchaintest.InterchainBuildOptions{
		TestName:  t.Name(),
		Client:    client,
		NetworkID: network,
		// BlockDatabaseFile: interchaintest.DefaultBlockDatabaseFilepath(),
		SkipPathCreation: false,
	})
	require.NoError(t, err)

	t.Cleanup(func() {
		_ = ic.Close()
	})
}

func modifyGenesisStrictUptime(cc ibc.ChainConfig, b []byte) ([]byte, error) {
	return modifyGenesisSlashingUptime(10, 0.9)(cc, b)
}

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

func horcruxSidecar(ctx context.Context, node *cosmos.ChainNode, name string, client *client.Client, network string, startupFlags ...string) (*cosmos.SidecarProcess, error) {
	startCmd := []string{binary, "start"}
	startCmd = append(startCmd, startupFlags...)
	if err := node.NewSidecarProcess(
		ctx, true, name, client, network,
		ibc.DockerImage{Repository: signerImage, Version: "latest", UidGid: "2345:2345"},
		"/home/horcrux", []string{signerPortDocker}, startCmd,
	); err != nil {
		return nil, err
	}

	return node.Sidecars[len(node.Sidecars)-1], nil
}

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

func getValSigningInfo(tn *cosmos.ChainNode, address cometbytes.HexBytes) (*slashingtypes.QuerySigningInfoResponse, error) {
	valConsPrefix := fmt.Sprintf("%svalcons", tn.Chain.Config().Bech32Prefix)

	bech32ValConsAddress, err := bech32.ConvertAndEncode(valConsPrefix, address)
	if err != nil {
		return nil, err
	}
	return slashingtypes.NewQueryClient(tn.CliContext()).SigningInfo(context.Background(), &slashingtypes.QuerySigningInfoRequest{
		ConsAddress: bech32ValConsAddress,
	})
}

func requireHealthyValidator(t *testing.T, referenceNode *cosmos.ChainNode, validatorAddress cometbytes.HexBytes) {
	signingInfo, err := getValSigningInfo(referenceNode, validatorAddress)
	require.NoError(t, err)

	require.False(t, signingInfo.ValSigningInfo.Tombstoned)
	require.Equal(t, time.Unix(0, 0).UTC(), signingInfo.ValSigningInfo.JailedUntil)
	require.Zero(t, signingInfo.ValSigningInfo.MissedBlocksCounter)
}

// transferLeadership elects a new raft leader.
func transferLeadership(ctx context.Context, cosigner *cosmos.SidecarProcess) error {
	_, _, err := cosigner.Exec(ctx, []string{binary, "elect", strconv.FormatInt(int64(cosigner.Index+1), 10)}, nil)
	return err
}

func pollForLeader(ctx context.Context, logger Logger, cosigner *cosmos.SidecarProcess, expectedLeader string) error {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			leader, err := getLeader(ctx, cosigner)
			logger.Logf("{%s} => current leader: {%s}, expected leader: {%s}", cosigner.Name(), leader, expectedLeader)
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
