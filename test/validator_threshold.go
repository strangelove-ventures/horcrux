package test

import (
	"context"
	"encoding/json"
	"fmt"
	"testing"

	"github.com/cometbft/cometbft/crypto"
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

func testChainSingleNodeAndHorcruxThreshold(
	t *testing.T,
	totalValidators int, // total number of validators on chain (one horcrux + single node for the rest)
	totalSigners int, // total number of signers for the single horcrux validator
	threshold uint8, // key shard threshold, and therefore how many horcrux signers must participate to sign a block
	totalSentries int, // number of sentry nodes for the single horcrux validator
	sentriesPerSigner int, // how many sentries should each horcrux signer connect to (min: 1, max: totalSentries)
) {
	ctx := context.Background()
	chain, pubKey := startChainSingleNodeAndHorcruxThreshold(ctx, t, totalValidators, totalSigners, threshold, totalSentries, sentriesPerSigner)

	err := testutil.WaitForBlocks(ctx, 20, chain)
	require.NoError(t, err)

	requireHealthyValidator(t, chain.Validators[0], pubKey.Address())
}

func startChainSingleNodeAndHorcruxThreshold(
	ctx context.Context,
	t *testing.T,
	totalValidators int, // total number of validators on chain (one horcrux + single node for the rest)
	totalSigners int, // total number of signers for the single horcrux validator
	threshold uint8, // key shard threshold, and therefore how many horcrux signers must participate to sign a block
	totalSentries int, // number of sentry nodes for the single horcrux validator
	sentriesPerSigner int, // how many sentries should each horcrux signer connect to (min: 1, max: totalSentries)
) (*cosmos.CosmosChain, crypto.PubKey) {
	client, network := interchaintest.DockerSetup(t)
	logger := zaptest.NewLogger(t)

	var chain *cosmos.CosmosChain
	var pubKey crypto.PubKey

	startChain(
		ctx, t, logger, client, network, &chain, totalValidators, totalSentries, modifyGenesisStrictUptime,
		preGenesisSingleNodeAndHorcruxThreshold(ctx, logger, client, network, totalSigners, threshold, sentriesPerSigner, &chain, &pubKey),
	)

	return chain, pubKey
}

func preGenesisSingleNodeAndHorcruxThreshold(
	ctx context.Context,
	logger *zap.Logger,
	client *client.Client,
	network string,
	totalSigners int, // total number of signers for the single horcrux validator
	threshold uint8, // key shard threshold, and therefore how many horcrux signers must participate to sign a block
	sentriesPerSigner int, // how many sentries should each horcrux signer connect to (min: 1, max: totalSentries)
	chain **cosmos.CosmosChain,
	pubKey *crypto.PubKey) func(ibc.ChainConfig) error {
	return func(cc ibc.ChainConfig) error {
		horcruxValidator := (*chain).Validators[0]

		sentries := append(cosmos.ChainNodes{horcruxValidator}, (*chain).FullNodes...)

		pvPubKey, err := convertValidatorToHorcrux(
			ctx,
			logger,
			client,
			network,
			horcruxValidator,
			totalSigners,
			threshold,
			sentries,
			sentriesPerSigner,
		)
		if err != nil {
			return err
		}

		*pubKey = pvPubKey

		return nil
	}
}

func convertValidatorToHorcrux(
	ctx context.Context,
	logger *zap.Logger,
	client *client.Client,
	network string,
	validator *cosmos.ChainNode,
	totalSigners int,
	threshold uint8,
	sentries cosmos.ChainNodes,
	sentriesPerSigner int,
) (crypto.PubKey, error) {
	sentriesForCosigners := getSentriesForCosignerConnection(sentries, totalSigners, sentriesPerSigner)

	ed25519Shards, pvPubKey, err := getShardedPrivvalKey(ctx, validator, threshold, uint8(totalSigners))
	if err != nil {
		return nil, err
	}

	eciesShards, err := signer.CreateCosignerECIESShards(totalSigners)
	if err != nil {
		return nil, err
	}

	cosigners := make(signer.CosignersConfig, totalSigners)

	for i := 0; i < totalSigners; i++ {
		_, err := horcruxSidecar(ctx, validator, fmt.Sprintf("cosigner-%d", i+1), client, network)
		if err != nil {
			return nil, err
		}

		cosigners[i] = signer.CosignerConfig{
			ShardID: i + 1,
			P2PAddr: fmt.Sprintf("tcp://%s:%s", validator.Sidecars[i].HostName(), signerPort),
		}
	}

	for i := 0; i < totalSigners; i++ {
		cosigner := validator.Sidecars[i]

		sentriesForCosigner := sentriesForCosigners[i]
		chainNodes := make(signer.ChainNodes, len(sentriesForCosigner))
		for i, sentry := range sentriesForCosigner {
			chainNodes[i] = signer.ChainNode{
				PrivValAddr: fmt.Sprintf("tcp://%s:1234", sentry.HostName()),
			}
		}

		config := signer.Config{
			SignMode: signer.SignModeThreshold,
			ThresholdModeConfig: &signer.ThresholdModeConfig{
				Threshold:   int(threshold),
				Cosigners:   cosigners,
				GRPCTimeout: "1500ms",
				RaftTimeout: "1500ms",
			},
			ChainNodes: chainNodes,
		}

		if err := writeConfigAndKeysThreshold(ctx, validator.Chain.Config().ChainID, cosigner, config, eciesShards[i], ed25519Shards[i]); err != nil {
			return nil, err
		}
	}

	return pvPubKey, enablePrivvalListener(ctx, logger, sentries, client)
}

func getShardedPrivvalKey(ctx context.Context, node *cosmos.ChainNode, threshold uint8, shards uint8) ([]signer.CosignerEd25519Key, crypto.PubKey, error) {
	pvKey, err := getPrivvalKey(ctx, node)
	if err != nil {
		return nil, nil, err
	}

	ed25519Shards := signer.CreateCosignerEd25519Shards(pvKey, threshold, shards)

	return ed25519Shards, pvKey.PubKey, nil
}

func writeConfigAndKeysThreshold(
	ctx context.Context,
	chainID string,
	cosigner *cosmos.SidecarProcess,
	config signer.Config,
	eciesKey signer.CosignerECIESKey,
	ed25519Key signer.CosignerEd25519Key,
) error {
	configBz, err := json.Marshal(config)
	if err != nil {
		return fmt.Errorf("failed to marshal config to json: %w", err)
	}

	if err := cosigner.WriteFile(ctx, configBz, ".horcrux/config.yaml"); err != nil {
		return fmt.Errorf("failed to write config.yaml: %w", err)
	}

	eciesKeyBz, err := json.Marshal(&eciesKey)
	if err != nil {
		return fmt.Errorf("failed to marshal ecies key: %w", err)
	}

	if err := cosigner.WriteFile(ctx, eciesKeyBz, ".horcrux/ecies_keys.json"); err != nil {
		return fmt.Errorf("failed to write ecies_keys.json: %w", err)
	}

	ed25519KeyBz, err := json.Marshal(&ed25519Key)
	if err != nil {
		return fmt.Errorf("failed to marshal ed25519 shard: %w", err)
	}

	if err = cosigner.WriteFile(ctx, ed25519KeyBz, fmt.Sprintf(".horcrux/%s_shard.json", chainID)); err != nil {
		return fmt.Errorf("failed to write %s_shard.json: %w", chainID, err)
	}

	return nil
}

func getSentriesForCosignerConnection(sentries cosmos.ChainNodes, numSigners int, sentriesPerSigner int) []cosmos.ChainNodes {
	if sentriesPerSigner == 0 {
		sentriesPerSigner = len(sentries)
	}

	peers := make([]cosmos.ChainNodes, numSigners)
	numSentries := len(sentries)

	if sentriesPerSigner == 1 {
		// Each node in the signer cluster is connected to a unique sentry node
		singleSentryIndex := 0
		for i := 0; i < numSigners; i++ {
			if len(sentries) == 1 || numSigners > numSentries {
				peers[i] = append(peers[i], sentries[singleSentryIndex:singleSentryIndex+1]...)
				singleSentryIndex++
				if singleSentryIndex >= len(sentries) {
					singleSentryIndex = 0
				}
			} else {
				peers[i] = append(peers[i], sentries[i:i+1]...)
			}
		}

		// Each node in the signer cluster is connected to the number of sentry nodes specified by sentriesPerSigner
	} else if sentriesPerSigner > 1 {
		sentriesIndex := 0

		for i := 0; i < numSigners; i++ {
			// if we are indexing sentries up to the end of the slice
			switch {
			case sentriesIndex+sentriesPerSigner == numSentries:
				peers[i] = append(peers[i], sentries[sentriesIndex:]...)
				sentriesIndex++

				// if there aren't enough sentries left in the slice use the sentries left in slice,
				// calculate how many more are needed, then start back at the beginning of
				// the slice to grab the rest. After, check if index into slice of sentries needs reset
			case sentriesIndex+sentriesPerSigner > numSentries:
				remainingSentries := sentries[sentriesIndex:]
				peers[i] = append(peers[i], remainingSentries...)

				neededSentries := sentriesPerSigner - len(remainingSentries)
				peers[i] = append(peers[i], sentries[0:neededSentries]...)

				sentriesIndex++
				if sentriesIndex >= numSentries {
					sentriesIndex = 0
				}
			default:
				peers[i] = append(peers[i], sentries[sentriesIndex:sentriesIndex+sentriesPerSigner]...)
				sentriesIndex++
			}
		}
	}
	return peers
}
