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
	interchaintest "github.com/strangelove-ventures/interchaintest/v7"
	"github.com/strangelove-ventures/interchaintest/v7/chain/cosmos"
	"github.com/strangelove-ventures/interchaintest/v7/ibc"
	"github.com/strangelove-ventures/interchaintest/v7/testutil"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
	"golang.org/x/sync/errgroup"
)

const (
	testChain        = "gaia" // ghcr.io/strangelove-ventures/heighliner/gaia
	testChainVersion = "v10.0.2"
)

func startChain(
	ctx context.Context,
	t *testing.T,
	logger *zap.Logger,
	client *client.Client,
	network string,
	chain **cosmos.CosmosChain,
	totalValidators int, // total number of validators on chain (one horcrux + single node for the rest)
	totalSentries int, // number of sentry nodes for the single horcrux validator
	modifyGenesis func(cc ibc.ChainConfig, b []byte) ([]byte, error),
	preGenesis func(ibc.ChainConfig) error,
) {
	nv := totalValidators
	nf := totalSentries - 1

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

func modifyGenesisStrictUptime(cc ibc.ChainConfig, b []byte) ([]byte, error) {
	return modifyGenesisSlashingUptime(10, 0.9)(cc, b)
}

func modifyGenesisSlashingUptime(signedBlocksWindow uint64, minSignedPerWindow float64) func(cc ibc.ChainConfig, b []byte) ([]byte, error) {
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
	startCmd := []string{"horcrux", "start"}
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
