package test

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"testing"

	cometjson "github.com/cometbft/cometbft/libs/json"
	"github.com/cometbft/cometbft/privval"
	"github.com/docker/docker/client"
	"github.com/strangelove-ventures/horcrux/v3/signer"
	interchaintest "github.com/strangelove-ventures/interchaintest/v8"
	"github.com/strangelove-ventures/interchaintest/v8/chain/cosmos"
	"github.com/strangelove-ventures/interchaintest/v8/ibc"
	"github.com/strangelove-ventures/interchaintest/v8/testutil"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
	"go.uber.org/zap/zaptest"
)

// testChainSingleNodeAndHorcruxSingle tests a single chain with a single horcrux (single-sign mode) validator and single node validators for the rest.
func testChainSingleNodeAndHorcruxSingle(
	t *testing.T,
	totalValidators int, // total number of validators on chain (one horcrux + single node for the rest)
	totalSentries int, // number of sentry nodes for the single horcrux validator
) {
	ctx := context.Background()
	cw, pubKey := startChainSingleNodeAndHorcruxSingle(ctx, t, totalValidators, totalSentries)

	err := testutil.WaitForBlocks(ctx, 20, cw.chain)
	require.NoError(t, err)

	sha := sha256.Sum256(pubKey)
	requireHealthyValidator(t, cw.chain.Validators[0], sha[:20])
}

// startChainSingleNodeAndHorcruxSingle starts a single chain with a single horcrux (single-sign mode) validator and single node validators for the rest.
func startChainSingleNodeAndHorcruxSingle(
	ctx context.Context,
	t *testing.T,
	totalValidators int, // total number of validators on chain (one horcrux + single node for the rest)
	totalSentries int, // number of sentry nodes for the single horcrux validator
) (*chainWrapper, []byte) {
	client, network := interchaintest.DockerSetup(t)
	logger := zaptest.NewLogger(t)

	var pubKey []byte

	cw := &chainWrapper{
		totalValidators: totalValidators,
		totalSentries:   totalSentries,
		modifyGenesis:   modifyGenesisStrictUptime,
		preGenesis:      preGenesisSingleNodeAndHorcruxSingle(ctx, logger, client, network, &pubKey),
	}

	startChains(ctx, t, logger, client, network, cw)

	return cw, pubKey
}

// preGenesisSingleNodeAndHorcruxSingle performs the pre-genesis setup to convert the first validator to a horcrux (single-sign mode) validator.
func preGenesisSingleNodeAndHorcruxSingle(
	ctx context.Context,
	logger *zap.Logger,
	client *client.Client,
	network string,
	pubKey *[]byte) func(*chainWrapper) func(ibc.ChainConfig) error {
	return func(cw *chainWrapper) func(ibc.ChainConfig) error {
		return func(cc ibc.ChainConfig) error {
			horcruxValidator := cw.chain.Validators[0]

			pvKey, err := getPrivvalKey(ctx, horcruxValidator)
			if err != nil {
				return err
			}

			*pubKey = pvKey.PubKey.Bytes()

			sentries := append(cosmos.ChainNodes{horcruxValidator}, cw.chain.FullNodes...)

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

			if err := writeConfigAndKeysSingle(ctx, cw.chain.Config().ChainID, singleSigner, config, pvKey); err != nil {
				return err
			}

			if err := singleSigner.CreateContainer(ctx); err != nil {
				return err
			}

			if err := singleSigner.StartContainer(ctx); err != nil {
				return err
			}

			return enablePrivvalListener(ctx, logger, sentries, client)
		}
	}
}

// writeConfigAndKeysSingle writes the config and keys for a horcrux single signer to the sidecar's docker volume.
func writeConfigAndKeysSingle(
	ctx context.Context,
	chainID string,
	singleSigner *cosmos.SidecarProcess,
	config signer.Config,
	key *privval.FilePVKey,
) error {
	configBz, err := json.Marshal(config)
	if err != nil {
		return fmt.Errorf("failed to marshal config to json: %w", err)
	}

	if err := singleSigner.WriteFile(ctx, configBz, ".horcrux/config.yaml"); err != nil {
		return fmt.Errorf("failed to write config.yaml: %w", err)
	}

	pvKeyBz, err := cometjson.Marshal(key)
	if err != nil {
		return fmt.Errorf("failed to marshal priv validator key: %w", err)
	}

	if err = singleSigner.WriteFile(ctx, pvKeyBz, fmt.Sprintf(".horcrux/%s_priv_validator_key.json", chainID)); err != nil {
		return fmt.Errorf("failed to write priv_validator_key.json: %w", err)
	}

	return nil
}
