package test

import (
	"context"
	"encoding/json"
	"fmt"
	"testing"

	"github.com/cometbft/cometbft/crypto"
	cometjson "github.com/cometbft/cometbft/libs/json"
	"github.com/cometbft/cometbft/privval"
	"github.com/docker/docker/client"
	"github.com/strangelove-ventures/horcrux/signer"
	interchaintest "github.com/strangelove-ventures/interchaintest/v7"
	"github.com/strangelove-ventures/interchaintest/v7/chain/cosmos"
	"github.com/strangelove-ventures/interchaintest/v7/ibc"
	"github.com/strangelove-ventures/interchaintest/v7/testutil"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
	"go.uber.org/zap/zaptest"
)

func testChainSingleNodeAndHorcruxSingle(
	t *testing.T,
	totalValidators int, // total number of validators on chain (one horcrux + single node for the rest)
	totalSentries int, // number of sentry nodes for the single horcrux validator
) {
	ctx := context.Background()
	chain, pubKey := startChainSingleNodeAndHorcruxSingle(ctx, t, totalValidators, totalSentries)

	err := testutil.WaitForBlocks(ctx, 20, chain)
	require.NoError(t, err)

	requireHealthyValidator(t, chain.Validators[0], pubKey.Address())
}

func startChainSingleNodeAndHorcruxSingle(
	ctx context.Context,
	t *testing.T,
	totalValidators int, // total number of validators on chain (one horcrux + single node for the rest)
	totalSentries int, // number of sentry nodes for the single horcrux validator
) (*cosmos.CosmosChain, crypto.PubKey) {
	client, network := interchaintest.DockerSetup(t)
	logger := zaptest.NewLogger(t)

	var chain *cosmos.CosmosChain
	var pubKey crypto.PubKey

	startChain(
		ctx, t, logger, client, network, &chain, totalValidators, totalSentries, modifyGenesisStrictUptime,
		preGenesisSingleNodeAndHorcruxSingle(ctx, logger, client, network, &chain, &pubKey),
	)

	return chain, pubKey
}

func preGenesisSingleNodeAndHorcruxSingle(
	ctx context.Context,
	logger *zap.Logger,
	client *client.Client,
	network string,
	chain **cosmos.CosmosChain,
	pubKey *crypto.PubKey) func(ibc.ChainConfig) error {
	return func(cc ibc.ChainConfig) error {
		horcruxValidator := (*chain).Validators[0]

		pvKey, err := getPrivvalKey(ctx, horcruxValidator)
		if err != nil {
			return err
		}

		*pubKey = pvKey.PubKey

		sentries := append(cosmos.ChainNodes{horcruxValidator}, (*chain).FullNodes...)

		singleSigner, err := horcruxSidecar(ctx, horcruxValidator, "signer", client, network, "--accept-risk")
		if err != nil {
			return err
		}

		chainNodes := make(signer.ChainNodes, len(sentries))
		for i, sentry := range sentries {
			chainNodes[i] = signer.ChainNode{
				PrivValAddr: fmt.Sprintf("tcp://%s:1234", sentry.HostName()),
			}
		}

		config := signer.Config{
			SignMode:   signer.SignModeSingle,
			ChainNodes: chainNodes,
		}

		if err := writeConfigAndKeysSingle(ctx, (*chain).Config().ChainID, singleSigner, config, pvKey); err != nil {
			return err
		}

		return enablePrivvalListener(ctx, logger, sentries, client)
	}
}

func writeConfigAndKeysSingle(
	ctx context.Context,
	chainID string,
	singleSigner *cosmos.SidecarProcess,
	config signer.Config,
	pvKey privval.FilePVKey,
) error {
	configBz, err := json.Marshal(config)
	if err != nil {
		return fmt.Errorf("failed to marshal config to json: %w", err)
	}

	if err := singleSigner.WriteFile(ctx, configBz, ".horcrux/config.yaml"); err != nil {
		return fmt.Errorf("failed to write config.yaml: %w", err)
	}

	pvKeyBz, err := cometjson.Marshal(pvKey)
	if err != nil {
		return fmt.Errorf("failed to marshal priv validator key: %w", err)
	}

	if err = singleSigner.WriteFile(ctx, pvKeyBz, fmt.Sprintf(".horcrux/%s_priv_validator_key.json", chainID)); err != nil {
		return fmt.Errorf("failed to write priv_validator_key.json: %w", err)
	}

	return nil
}
