package test

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"testing"
	"time"

	"github.com/cometbft/cometbft/crypto"
	"github.com/docker/docker/client"
	dto "github.com/prometheus/client_model/go"
	"github.com/prometheus/common/expfmt"
	"github.com/strangelove-ventures/horcrux/src/config"
	"github.com/strangelove-ventures/horcrux/src/cosigner/nodesecurity"
	tss "github.com/strangelove-ventures/horcrux/src/tss"
	interchaintest "github.com/strangelove-ventures/interchaintest/v8"
	"github.com/strangelove-ventures/interchaintest/v8/chain/cosmos"
	"github.com/strangelove-ventures/interchaintest/v8/ibc"
	"github.com/strangelove-ventures/interchaintest/v8/testutil"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
	"go.uber.org/zap/zaptest"
	"golang.org/x/sync/errgroup"
	"gopkg.in/yaml.v3"
)

// testChainSingleNodeAndHorcruxThreshold tests a single chain with a single horcrux (threshold mode) validator and single node validators for the rest of the validators.
func testChainSingleNodeAndHorcruxThreshold(
	t *testing.T,
	totalValidators int, // total number of validators on chain (one horcrux + single node for the rest)
	totalSigners int, // total number of signers for the single horcrux validator
	threshold uint8, // key shard threshold, and therefore how many horcrux signers must participate to sign a block
	totalSentries int, // number of sentry cosigner for the single horcrux validator
	sentriesPerSigner int, // how many sentries should each horcrux signer connect to (min: 1, max: totalSentries)
) {
	ctx := context.Background()
	cw, pubKey := startChainSingleNodeAndHorcruxThreshold(ctx, t, totalValidators, totalSigners, threshold, totalSentries, sentriesPerSigner)

	ourValidator := cw.chain.Validators[0]
	cosigners := ourValidator.Sidecars
	go getCosignerMetrics(ctx, cosigners)

	err := testutil.WaitForBlocks(ctx, 20, cw.chain)
	require.NoError(t, err)

	requireHealthyValidator(t, ourValidator, pubKey.Address())
}

// startChainSingleNodeAndHorcruxThreshold starts a single chain with a single horcrux (threshold mode) validator and single node validators for the rest of the validators.
func startChainSingleNodeAndHorcruxThreshold(
	ctx context.Context,
	t *testing.T,
	totalValidators int, // total number of validators on chain (one horcrux + single node for the rest)
	totalSigners int, // total number of signers for the single horcrux validator
	threshold uint8, // key shard threshold, and therefore how many horcrux signers must participate to sign a block
	totalSentries int, // number of sentry cosigner for the single horcrux validator
	sentriesPerSigner int, // how many sentries should each horcrux signer connect to (min: 1, max: totalSentries)
) (*chainWrapper, crypto.PubKey) {
	client, network := interchaintest.DockerSetup(t)
	logger := zaptest.NewLogger(t)

	var chain *cosmos.CosmosChain
	var pubKey crypto.PubKey

	cw := &chainWrapper{
		chain:           chain,
		totalValidators: totalValidators,
		totalSentries:   totalSentries - 1,
		modifyGenesis:   modifyGenesisStrictUptime,
		preGenesis:      preGenesisSingleNodeAndHorcruxThreshold(ctx, logger, client, network, totalSigners, threshold, sentriesPerSigner, &pubKey),
	}

	startChains(ctx, t, logger, client, network, cw)

	return cw, pubKey
}

// preGenesisSingleNodeAndHorcruxThreshold performs the pre-genesis setup to convert the first validator to a horcrux (threshold mode) validator.
func preGenesisSingleNodeAndHorcruxThreshold(
	ctx context.Context,
	logger *zap.Logger,
	client *client.Client,
	network string,
	totalSigners int, // total number of signers for the single horcrux validator
	threshold uint8, // key shard threshold, and therefore how many horcrux signers must participate to sign a block
	sentriesPerSigner int, // how many sentries should each horcrux signer connect to (min: 1, max: totalSentries)
	pubKey *crypto.PubKey) func(*chainWrapper) func(ibc.ChainConfig) error {
	return func(cw *chainWrapper) func(ibc.ChainConfig) error {
		return func(cc ibc.ChainConfig) error {
			horcruxValidator := cw.chain.Validators[0]

			sentries := append(cosmos.ChainNodes{horcruxValidator}, cw.chain.FullNodes...)

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
}

// preGenesisAllHorcruxThreshold performs the pre-genesis setup to convert all validators to horcrux validators.
func preGenesisAllHorcruxThreshold(
	ctx context.Context,
	logger *zap.Logger,
	client *client.Client,
	network string,
	totalSigners int, // total number of signers for the single horcrux validator
	threshold uint8, // key shard threshold, and therefore how many horcrux signers must participate to sign a block
	sentriesPerValidator int, // how many sentries for each horcrux validator (min: sentriesPerSigner, max: totalSentries)
	sentriesPerSigner int, // how many sentries should each horcrux signer connect to (min: 1, max: sentriesPerValidator)

	pubKeys []crypto.PubKey) func(*chainWrapper) func(ibc.ChainConfig) error {
	return func(cw *chainWrapper) func(ibc.ChainConfig) error {
		return func(cc ibc.ChainConfig) error {
			fnsPerVal := sentriesPerValidator - 1 // minus 1 for the validator itself
			var eg errgroup.Group
			for i, validator := range cw.chain.Validators {
				validator := validator
				i := i
				sentries := append(cosmos.ChainNodes{validator}, cw.chain.FullNodes[i*fnsPerVal:(i+1)*fnsPerVal]...)

				eg.Go(func() error {
					pvPubKey, err := convertValidatorToHorcrux(
						ctx,
						logger,
						client,
						network,
						validator,
						totalSigners,
						threshold,
						sentries,
						sentriesPerSigner,
					)

					if err != nil {
						return err
					}

					pubKeys[i] = pvPubKey

					return nil
				})
			}

			return eg.Wait()
		}
	}
}

// convertValidatorToHorcrux converts a validator to a horcrux validator by creating horcrux and
// configuring cosigners which will startup as sidecar processes for the validator.
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

	eciesShards, err := nodesecurity.CreateCosignerECIESShards(totalSigners)
	if err != nil {
		return nil, err
	}

	cosigners := make(config.CosignersConfig, totalSigners)

	for i := 0; i < totalSigners; i++ {
		_, err := horcruxSidecar(ctx, validator, fmt.Sprintf("cosigner-%d", i+1), client, network)
		if err != nil {
			return nil, err
		}

		cosigners[i] = config.CosignerConfig{
			ShardID: i + 1,
			P2PAddr: fmt.Sprintf("tcp://%s:%s", validator.Sidecars[i].HostName(), signerPort),
		}
	}

	var eg errgroup.Group
	for i := 0; i < totalSigners; i++ {
		cosigner := validator.Sidecars[i]

		sentriesForCosigner := sentriesForCosigners[i]
		chainNodes := make(config.ChainNodes, len(sentriesForCosigner))
		for i, sentry := range sentriesForCosigner {
			chainNodes[i] = config.ChainNode{
				PrivValAddr: fmt.Sprintf("tcp://%s:1234", sentry.HostName()),
			}
		}

		config := config.Config{
			SignMode: config.SignModeThreshold,
			ThresholdModeConfig: &config.ThresholdModeConfig{
				Threshold:   int(threshold),
				Cosigners:   cosigners,
				GRPCTimeout: "200ms",
				RaftTimeout: "200ms",
			},
			ChainNodes: chainNodes,
			DebugAddr:  fmt.Sprintf("0.0.0.0:%s", debugPort),
		}

		i := i

		eg.Go(func() error {
			if err := writeConfigAndKeysThreshold(
				ctx, cosigner, config, eciesShards[i],
				chainEd25519Shard{chainID: validator.Chain.Config().ChainID, key: ed25519Shards[i]},
			); err != nil {
				return err
			}

			if err := cosigner.CreateContainer(ctx); err != nil {
				return err
			}

			return cosigner.StartContainer(ctx)
		})
	}

	if err := eg.Wait(); err != nil {
		return nil, err
	}

	return pvPubKey, enablePrivvalListener(ctx, logger, sentries, client)
}

// getPrivvalKey gets the privval key from the validator and creates threshold shards from it.
func getShardedPrivvalKey(ctx context.Context, node *cosmos.ChainNode, threshold uint8, shards uint8) ([]tss.Ed25519Key, crypto.PubKey, error) {
	pvKey, err := getPrivvalKey(ctx, node)
	if err != nil {
		return nil, nil, err
	}

	vaultKeys, err := tss.GeneratePersistentThresholdSignShards(pvKey.PrivKey.Bytes(), pvKey.PubKey, threshold, shards)

	return vaultKeys, pvKey.PubKey, nil
}

// chainEd25519Shard is a wrapper for a chain Index and a shard of an ed25519 consensus key.
type chainEd25519Shard struct {
	chainID string
	key     tss.Ed25519Key
}

// writeConfigAndKeysThreshold writes the config and keys for a horcrux cosigner to the sidecar's docker volume.
func writeConfigAndKeysThreshold(
	ctx context.Context,
	cosigner *cosmos.SidecarProcess,
	config config.Config,
	eciesKey nodesecurity.CosignerECIESKey,
	ed25519Shards ...chainEd25519Shard,
) error {
	configBz, err := yaml.Marshal(config)
	if err != nil {
		return fmt.Errorf("failed to marshal config to yaml: %w", err)
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

	for _, key := range ed25519Shards {
		ed25519KeyBz, err := json.Marshal(&key.key)
		if err != nil {
			return fmt.Errorf("failed to marshal ed25519 shard: %w", err)
		}

		if err = cosigner.WriteFile(ctx, ed25519KeyBz, fmt.Sprintf(".horcrux/%s_shard.json", key.chainID)); err != nil {
			return fmt.Errorf("failed to write %s_shard.json: %w", key.chainID, err)
		}
	}

	return nil
}

// getSentriesForCosignerConnection will return a slice of sentries for each cosigner to connect to.
// The sentries will be picked for each cosigner in a round robin.
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

		// Each node in the signer cluster is connected to the number of sentry cosigner specified by sentriesPerSigner
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
func getCosignerMetrics(ctx context.Context, cosigners cosmos.SidecarProcesses) {
	for _, s := range cosigners {
		s := s
		ticker := time.NewTicker(time.Second)

		go func() {
			defer ticker.Stop()
			for {
				select {
				case <-ctx.Done():
					return
				case <-ticker.C:
					m, err := getMetrics(ctx, s)
					if err != nil {
						fmt.Printf("{%s} -> Error getting metrics : %v", s.Name(), err)
					}
					fmt.Println("Got Metrics", m)
				}
			}
		}()
	}
}

func getMetrics(ctx context.Context, cosigner *cosmos.SidecarProcess) (map[string]*dto.MetricFamily, error) {

	debugAddr, err := cosigner.GetHostPorts(ctx, debugPortDocker)
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, "GET", "http://"+debugAddr[0]+"/metrics", nil)

	if err != nil {

		return nil, err
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var parser expfmt.TextParser
	mf, err := parser.TextToMetricFamilies(resp.Body)
	if err != nil {

		return nil, err
	}

	return mf, nil
}
