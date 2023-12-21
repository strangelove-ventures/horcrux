package test

import (
	"context"
	"fmt"
	"sync"
	"testing"

	"github.com/cometbft/cometbft/crypto"
	dockertypes "github.com/docker/docker/api/types"
	"github.com/strangelove-ventures/horcrux/v3/signer"
	interchaintest "github.com/strangelove-ventures/interchaintest/v8"
	"github.com/strangelove-ventures/interchaintest/v8/chain/cosmos"
	"github.com/strangelove-ventures/interchaintest/v8/ibc"
	"github.com/strangelove-ventures/interchaintest/v8/testutil"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap/zaptest"
	"golang.org/x/sync/errgroup"
)

const (
	chainID                    = "horcrux"
	maxSpecificElectionRetries = 3
)

// Test2Of3SignerOneSentry will spin up a chain with one single-node validator and one horcrux validator
// the horcrux validator will have three cosigner nodes with a threshold of two, and one sentry node
func Test2Of3SignerOneSentry(t *testing.T) {
	testChainSingleNodeAndHorcruxThreshold(t, 2, 3, 2, 1, 1)
}

// Test2Of3SignerTwoSentries will spin up a chain with one single-node validator and one horcrux validator
// the horcrux validator will have three cosigner nodes with a threshold of two, and two sentry nodes
// checks that no slashing occurs
func Test2Of3SignerTwoSentries(t *testing.T) {
	testChainSingleNodeAndHorcruxThreshold(t, 2, 3, 2, 2, 2)
}

// Test2Of3SignerThreeSentries will spin up a chain with one single-node validator and one horcrux validator
// the horcrux validator will have three cosigner nodes with a threshold of two, and three sentry nodes
// where each cosigner connects to all sentries
func Test2Of3SignerThreeSentries(t *testing.T) {
	testChainSingleNodeAndHorcruxThreshold(t, 2, 3, 2, 3, 3)
}

// Test2Of3SignerThreeSentriesUniqueConnection will spin up a chain with one single-node validator and one horcrux validator
// the horcrux validator will have three cosigner nodes with a threshold of two, and three sentry nodes
// where each cosigner only connects to one sentry
func Test2Of3SignerThreeSentriesUniqueConnection(t *testing.T) {
	testChainSingleNodeAndHorcruxThreshold(t, 2, 3, 2, 3, 1)
}

// Test2Of3SignerOneSentry will spin up a chain with one single-node validator and one horcrux validator
// the horcrux validator will have three cosigner nodes with a threshold of two, and one sentry node
func Test3Of5SignerOneSentry(t *testing.T) {
	testChainSingleNodeAndHorcruxThreshold(t, 2, 5, 3, 1, 1)
}

// Test3Of5SignerTwoSentries will spin up a chain with one single-node validator and one horcrux validator
// the horcrux validator will have five cosigner nodes with a threshold of three, and two sentry nodes
// where each cosigner connects to all sentries.
func Test3Of5SignerTwoSentries(t *testing.T) {
	testChainSingleNodeAndHorcruxThreshold(t, 2, 5, 3, 2, 2)
}

// Test3Of5SignerFiveSentries will spin up a chain with one single-node validator and one horcrux validator
// the horcrux validator will have five cosigner nodes with a threshold of three, and five sentry nodes
// where each cosigner connects to all sentries.
func Test3Of5SignerFiveSentries(t *testing.T) {
	testChainSingleNodeAndHorcruxThreshold(t, 2, 5, 3, 5, 5)
}

// Test3Of5SignerFiveSentriesUniqueConnection will spin up a chain with one single-node validator and one horcrux validator
// the horcrux validator will have three cosigner nodes with a threshold of two, and three sentry nodes
// where each cosigner only connects to one sentry.
func Test3Of5SignerFiveSentriesUniqueConnection(t *testing.T) {
	testChainSingleNodeAndHorcruxThreshold(t, 2, 5, 3, 5, 1)
}

// Test4Of7SignerTwoSentries will spin up a chain with one single-node validator and one horcrux validator
// the horcrux validator will have seven cosigner nodes with a threshold of four, and two sentry nodes
// where each cosigner connects to all sentries.
func Test4Of7SignerTwoSentries(t *testing.T) {
	testChainSingleNodeAndHorcruxThreshold(t, 2, 7, 4, 2, 2)
}

// TestSingleSignerTwoSentries will spin up a chain with one single-node validator and one horcrux single
// signer validator.
func TestSingleSignerTwoSentries(t *testing.T) {
	testChainSingleNodeAndHorcruxSingle(t, 2, 2)
}

// TestUpgradeValidatorToHorcrux will spin up a chain with two validators, stop one validator, configure that validator
// to be a relay for the remote signer cluster, spin up a 2/3 threshold signer cluster, restart the validator and check
// that no slashing occurs.
func TestUpgradeValidatorToHorcrux(t *testing.T) {
	ctx := context.Background()
	client, network := interchaintest.DockerSetup(t)
	logger := zaptest.NewLogger(t)

	const (
		totalValidators    = 2
		signedBlocksWindow = 10
		minSignedPerWindow = 0.5
		totalSigners       = 3
		threshold          = 2
		sentriesPerSigner  = 1
	)

	// slightly more lenient uptime requirement than modifyGenesisStrictUptime to account for
	// the time it takes to upgrade the validator, where a few missed blocks is expected.
	// allow 50% missed blocks in 10 block signed blocks window (5 missed blocks before slashing).
	modifyGenesis := modifyGenesisSlashingUptime(signedBlocksWindow, minSignedPerWindow)

	cw := &chainWrapper{
		totalValidators: totalValidators,
		modifyGenesis:   modifyGenesis,
	}

	startChains(ctx, t, logger, client, network, cw)

	// validator to upgrade to horcrux
	v := cw.chain.Validators[0]

	err := v.StopContainer(ctx)
	require.NoError(t, err)

	pubKey, err := convertValidatorToHorcrux(ctx, logger, client, network, v, totalSigners, threshold, cosmos.ChainNodes{v}, sentriesPerSigner)
	require.NoError(t, err)

	err = v.StartContainer(ctx)
	require.NoError(t, err)

	err = testutil.WaitForBlocks(ctx, 20, cw.chain)
	require.NoError(t, err)

	requireHealthyValidator(t, cw.chain.Validators[0], pubKey.Address())
}

// TestDownedSigners2of3 tests taking down 2 nodes at a time in the 2/3 threshold horcrux cluster for a period of time.
func TestDownedSigners2of3(t *testing.T) {
	ctx := context.Background()

	const (
		totalValidators   = 4
		totalSigners      = 3
		threshold         = 2
		totalSentries     = 3
		sentriesPerSigner = 3
	)

	cw, pubKey := startChainSingleNodeAndHorcruxThreshold(
		ctx, t, totalValidators, totalSigners, threshold, totalSentries, sentriesPerSigner,
	)

	require.NoError(t, testutil.WaitForBlocks(ctx, 15, cw.chain))

	ourValidator := cw.chain.Validators[0]
	requireHealthyValidator(t, ourValidator, pubKey.Address())

	cosigners := ourValidator.Sidecars

	// Test taking down each node in the signer cluster for a period of time
	for _, cosigner := range cosigners {
		t.Logf("{%s} -> Stopping signer...", cosigner.Name())
		require.NoError(t, cosigner.StopContainer(ctx))

		t.Logf("{%s} -> Waiting for blocks after stopping cosigner {%s}", ourValidator.Name(), cosigner.Name())
		require.NoError(t, testutil.WaitForBlocks(ctx, 15, cw.chain))

		requireHealthyValidator(t, ourValidator, pubKey.Address())

		t.Logf("{%s} -> Restarting signer...", cosigner.Name())
		require.NoError(t, cosigner.StartContainer(ctx))

		t.Logf("{%s} -> Waiting for blocks after restarting cosigner {%s}", ourValidator.Name(), cosigner.Name())
		require.NoError(t, testutil.WaitForBlocks(ctx, 15, cw.chain))

		requireHealthyValidator(t, ourValidator, pubKey.Address())
	}
}

// TestDownedSigners3of5 tests taking down 2 nodes at a time in the 3/5 threshold horcrux cluster for a period of time.
func TestDownedSigners3of5(t *testing.T) {
	ctx := context.Background()

	const (
		totalValidators   = 4
		totalSigners      = 5
		threshold         = 3
		totalSentries     = 3
		sentriesPerSigner = 3
	)

	cw, pubKey := startChainSingleNodeAndHorcruxThreshold(
		ctx, t, totalValidators, totalSigners, threshold, totalSentries, sentriesPerSigner,
	)

	require.NoError(t, testutil.WaitForBlocks(ctx, 15, cw.chain))

	ourValidator := cw.chain.Validators[0]
	requireHealthyValidator(t, ourValidator, pubKey.Address())

	cosigners := ourValidator.Sidecars

	// Test taking down 2 nodes at a time in the signer cluster for a period of time
	for i := 0; i < len(cosigners); i++ {
		cosigner1 := cosigners[i]
		var cosigner2 *cosmos.SidecarProcess
		if i < len(cosigners)-1 {
			cosigner2 = cosigners[i+1]
		} else {
			cosigner2 = cosigners[0]
		}
		if i == 0 {
			t.Logf("{%s} -> Stopping signer...", cosigner1.Name())
			require.NoError(t, cosigner1.StopContainer(ctx))
			t.Logf("{%s} -> Stopping signer...", cosigner2.Name())
			require.NoError(t, cosigner2.StopContainer(ctx))
			t.Logf("{%s} -> Waiting for blocks after stopping cosigner {%s}", ourValidator.Name(), cosigner1.Name())
		} else {
			t.Logf("{%s} -> Stopping signer...", cosigner2.Name())
			require.NoError(t, cosigner2.StopContainer(ctx))
		}

		t.Logf("{%s} -> Waiting for blocks after stopping cosigner {%s}", ourValidator.Name(), cosigner2.Name())
		require.NoError(t, testutil.WaitForBlocks(ctx, 15, cw.chain))

		requireHealthyValidator(t, ourValidator, pubKey.Address())

		t.Logf("{%s} -> Restarting cosigner...", cosigner1.Name())
		require.NoError(t, cosigner1.StartContainer(ctx))
		require.NoError(t, testutil.WaitForBlocks(ctx, 15, cw.chain))

		requireHealthyValidator(t, ourValidator, pubKey.Address())
	}
}

// TestLeaderElection2of3 tests electing a specific leader in a 2/3 threshold horcrux cluster.
func TestLeaderElection2of3(t *testing.T) {
	ctx := context.Background()

	const (
		totalValidators   = 2
		totalSigners      = 3
		threshold         = 2
		totalSentries     = 3
		sentriesPerSigner = 3
	)

	cw, pubKey := startChainSingleNodeAndHorcruxThreshold(
		ctx, t, totalValidators, totalSigners, threshold, totalSentries, sentriesPerSigner,
	)

	ourValidator := cw.chain.Validators[0]
	requireHealthyValidator(t, ourValidator, pubKey.Address())

	cosigners := ourValidator.Sidecars

	// Test electing each node in the signer cluster for a period of time
	for _, cosigner := range cosigners {
		var eg errgroup.Group

		for i := 0; i < maxSpecificElectionRetries; i++ {
			t.Logf("{%s} -> Electing leader...", cosigner.Name())
			err := transferLeadership(ctx, cosigner)
			require.NoError(t, err, "failed to transfer leadership to %d", cosigner.Name())

			t.Logf("{%s} -> Waiting for signed blocks with signer as leader {%s}", ourValidator.Name(), cosigner.Name())

			// Make sure all cosigners have the same leader
			for _, s := range cosigners {
				s := s
				eg.Go(func() error {
					return pollForLeader(ctx, t, s, cosigner.Index+1)
				})
			}
			if err := eg.Wait(); err == nil {
				break
			}

			// electing a specific leader can fail, but this is okay as long as all nodes agree on one leader.
			// will retry electing the specific leader in the next iteration.
			var commonLeader int
			for i, s := range cosigners {
				leader, err := getLeader(ctx, s)
				require.NoErrorf(t, err, "failed to get leader from signer: %s", s.Name())
				if i == 0 {
					commonLeader = leader
					continue
				}
				require.Equal(t, commonLeader, leader, "leader is not the same on all signers, mismatch on %s", s.Name())
			}
		}

		require.NoError(t, testutil.WaitForBlocks(ctx, 5, cw.chain))

		requireHealthyValidator(t, ourValidator, pubKey.Address())
	}
}

// TestChainPureHorcrux tests a chain with only horcrux validators.
func TestChainPureHorcrux(t *testing.T) {
	ctx := context.Background()
	client, network := interchaintest.DockerSetup(t)
	logger := zaptest.NewLogger(t)

	const (
		totalValidators      = 2
		sentriesPerValidator = 3
		signersPerValidator  = 3
		threshold            = 2
		sentriesPerSigner    = 1
	)

	pubKeys := make([]crypto.PubKey, totalValidators)
	cw := &chainWrapper{
		totalValidators: totalValidators,
		totalSentries:   1 + totalValidators*(sentriesPerValidator-1),
		modifyGenesis:   modifyGenesisStrictUptime,
		preGenesis:      preGenesisAllHorcruxThreshold(ctx, logger, client, network, signersPerValidator, threshold, sentriesPerValidator, sentriesPerSigner, pubKeys),
	}

	startChains(
		ctx, t, logger, client, network, cw,
	)

	err := testutil.WaitForBlocks(ctx, 20, cw.chain)
	require.NoError(t, err)

	for _, p := range pubKeys {
		requireHealthyValidator(t, cw.chain.Validators[0], p.Address())
	}
}

// TestMultipleChainHorcrux tests running a validator across multiple chains with a single horcrux cluster.
func TestMultipleChainHorcrux(t *testing.T) {
	ctx := context.Background()
	client, network := interchaintest.DockerSetup(t)
	logger := zaptest.NewLogger(t)

	const (
		totalChains          = 2
		validatorsPerChain   = 2
		sentriesPerValidator = 3
		totalSigners         = 3
		threshold            = 2
		sentriesPerSigner    = 1
	)

	chainWrappers := make([]*chainWrapper, totalChains)
	pubKeys := make([]crypto.PubKey, totalChains)
	chainConfigs := make([]*cosignerChainConfig, totalChains)
	preGenesises := make([]func(*chainWrapper) func(ibc.ChainConfig) error, totalChains)

	for i := 0; i < totalChains; i++ {
		chainConfigs[i] = &cosignerChainConfig{
			sentries: make([]cosmos.ChainNodes, sentriesPerSigner),
			shards:   make([]signer.CosignerEd25519Key, totalSigners),
		}
	}

	cosignerSidecars := make(horcruxSidecars, totalSigners)

	eciesShards, err := signer.CreateCosignerECIESShards(totalSigners)
	require.NoError(t, err)

	var wg sync.WaitGroup
	wg.Add(totalChains)

	cosignersStarted := make(chan struct{}, 1)

	for i, chainConfig := range chainConfigs {
		i := i
		chainConfig := chainConfig
		preGenesises[i] = func(cw *chainWrapper) func(ibc.ChainConfig) error {
			return func(cc ibc.ChainConfig) error {

				firstSentry := cw.chain.Validators[0]
				sentries := append(cosmos.ChainNodes{firstSentry}, cw.chain.FullNodes...)

				sentriesForCosigner := getSentriesForCosignerConnection(sentries, totalSigners, sentriesPerSigner)
				chainConfig.sentries = sentriesForCosigner

				chainConfig.chainID = cw.chain.Config().ChainID

				ed25519Shards, pvPubKey, err := getShardedPrivvalKey(ctx, firstSentry, threshold, uint8(totalSigners))
				if err != nil {
					wg.Done()
					return err
				}

				chainConfig.shards = ed25519Shards

				pubKeys[i] = pvPubKey

				if i == 0 {
					for j := 0; j < totalSigners; j++ {
						cosigner, err := horcruxSidecar(ctx, firstSentry, fmt.Sprintf("cosigner-%d", j+1), client, network)
						if err != nil {
							wg.Done()
							return err
						}

						cosignerSidecars[j] = horcruxSidecarProcess{
							cosigner: cosigner,
						}
					}
				}

				if err := enablePrivvalListener(ctx, logger, sentries, client); err != nil {
					wg.Done()
					return err
				}

				wg.Done()

				// wait for all cosigners to be started before continuing to start the chain.
				<-cosignersStarted

				return nil
			}
		}
	}

	go configureAndStartSidecars(ctx, t, eciesShards, cosignerSidecars, threshold, &wg, cosignersStarted, chainConfigs...)

	for i := 0; i < totalChains; i++ {
		chainWrappers[i] = &chainWrapper{
			totalValidators: validatorsPerChain,
			totalSentries:   sentriesPerValidator - 1,
			modifyGenesis:   modifyGenesisStrictUptime,
			preGenesis:      preGenesises[i],
		}
	}

	startChains(ctx, t, logger, client, network, chainWrappers...)

	chains := make([]testutil.ChainHeighter, totalChains)
	for i, cw := range chainWrappers {
		chains[i] = cw.chain
	}

	testutil.WaitForBlocks(ctx, 20, chains...)

	for i, p := range pubKeys {
		requireHealthyValidator(t, chainWrappers[i].chain.Validators[0], p.Address())
	}
}

type cosignerChainConfig struct {
	chainID  string
	shards   []signer.CosignerEd25519Key
	sentries []cosmos.ChainNodes
}

type horcruxSidecarProcess struct {
	cosigner *cosmos.SidecarProcess
	proxy    *cosmos.SidecarProcess
}

type horcruxSidecars []horcruxSidecarProcess

func configureAndStartSidecars(
	ctx context.Context,
	t *testing.T,
	eciesShards []signer.CosignerECIESKey,
	sidecars horcruxSidecars,
	threshold int,
	wg *sync.WaitGroup,
	cosignersStarted chan struct{},
	chainConfigs ...*cosignerChainConfig,
) {
	// wait for pre-genesis to finish from all chains
	wg.Wait()

	totalSigners := len(sidecars)

	cosignersConfig := make(signer.CosignersConfig, totalSigners)
	for i, s := range sidecars {
		cosignersConfig[i] = signer.CosignerConfig{
			ShardID: i + 1,
			P2PAddr: fmt.Sprintf("tcp://%s:%s", s.cosigner.HostName(), signerPort),
		}
	}

	var eg errgroup.Group

	for i, s := range sidecars {
		numSentries := 0
		for _, chainConfig := range chainConfigs {
			numSentries += len(chainConfig.sentries[i])
		}

		chainNodes := make(signer.ChainNodes, 0, numSentries)

		ed25519Shards := make([]chainEd25519Shard, len(chainConfigs))

		for j, chainConfig := range chainConfigs {
			if s.proxy == nil {
				for _, sentry := range chainConfig.sentries[i] {
					chainNodes = append(chainNodes, signer.ChainNode{
						PrivValAddr: fmt.Sprintf("tcp://%s:1234", sentry.HostName()),
					})
				}
			}

			ed25519Shards[j] = chainEd25519Shard{
				chainID: chainConfig.chainID,
				key:     chainConfig.shards[i],
			}
		}

		var grpcAddr string
		if s.proxy != nil {
			grpcAddr = ":5555"
		}

		config := signer.Config{
			SignMode: signer.SignModeThreshold,
			ThresholdModeConfig: &signer.ThresholdModeConfig{
				Threshold:   threshold,
				Cosigners:   cosignersConfig,
				GRPCTimeout: "200ms",
				RaftTimeout: "200ms",
			},
			ChainNodes: chainNodes,
			GRPCAddr:   grpcAddr,
		}

		cosigner := s.cosigner
		proxy := s.proxy
		i := i

		if proxy != nil {
			eg.Go(func() error {
				if err := proxy.CreateContainer(ctx); err != nil {
					return err
				}

				return proxy.StartContainer(ctx)
			})
		}

		// configure and start cosigner in parallel
		eg.Go(func() error {
			if err := writeConfigAndKeysThreshold(ctx, cosigner, config, eciesShards[i], ed25519Shards...); err != nil {
				return err
			}

			if err := cosigner.CreateContainer(ctx); err != nil {
				return err
			}

			return cosigner.StartContainer(ctx)
		})
	}

	require.NoError(t, eg.Wait())

	// signal to pre-genesis that all cosigners have been started and chain start can proceed.
	close(cosignersStarted)
}

func TestHorcruxProxyGRPC(t *testing.T) {
	ctx := context.Background()
	client, network := interchaintest.DockerSetup(t)
	logger := zaptest.NewLogger(t)

	_, err := client.ImagePull(
		ctx,
		horcruxProxyRegistry+":"+horcruxProxyTag,
		dockertypes.ImagePullOptions{},
	)
	require.NoError(t, err)

	const (
		totalChains          = 2
		validatorsPerChain   = 2
		sentriesPerValidator = 3
		totalSigners         = 3
		threshold            = 2
		sentriesPerSigner    = 1
	)

	chainWrappers := make([]*chainWrapper, totalChains)
	pubKeys := make([]crypto.PubKey, totalChains)
	chainConfigs := make([]*cosignerChainConfig, totalChains)
	preGenesises := make([]func(*chainWrapper) func(ibc.ChainConfig) error, totalChains)

	for i := 0; i < totalChains; i++ {
		chainConfigs[i] = &cosignerChainConfig{
			sentries: make([]cosmos.ChainNodes, sentriesPerSigner),
			shards:   make([]signer.CosignerEd25519Key, totalSigners),
		}
	}

	cosignerSidecars := make(horcruxSidecars, totalSigners)

	eciesShards, err := signer.CreateCosignerECIESShards(totalSigners)
	require.NoError(t, err)

	var wg sync.WaitGroup
	wg.Add(totalChains)

	cosignersStarted := make(chan struct{}, 1)

	var configWg sync.WaitGroup
	configWg.Add(totalChains)

	for i, chainConfig := range chainConfigs {
		i := i
		chainConfig := chainConfig
		preGenesises[i] = func(cw *chainWrapper) func(ibc.ChainConfig) error {
			return func(cc ibc.ChainConfig) error {

				firstSentry := cw.chain.Validators[0]
				sentries := append(cosmos.ChainNodes{firstSentry}, cw.chain.FullNodes...)

				sentriesForCosigner := getSentriesForCosignerConnection(sentries, totalSigners, sentriesPerSigner)
				chainConfig.sentries = sentriesForCosigner

				configWg.Done()

				chainConfig.chainID = cw.chain.Config().ChainID

				ed25519Shards, pvPubKey, err := getShardedPrivvalKey(ctx, firstSentry, threshold, uint8(totalSigners))
				if err != nil {
					wg.Done()
					return err
				}

				chainConfig.shards = ed25519Shards

				pubKeys[i] = pvPubKey

				if i == 0 {
					configWg.Wait()
					for j := 0; j < totalSigners; j++ {
						var h horcruxSidecarProcess
						cosigner, err := horcruxSidecar(ctx, firstSentry, fmt.Sprintf("cosigner-%d", j+1), client, network)
						if err != nil {
							wg.Done()
							return err
						}

						h.cosigner = cosigner

						startArgs := []string{
							"-g", fmt.Sprintf("%s:%s", cosigner.HostName(), grpcPort),
							"-o=false",
						}

						for _, chainConfig := range chainConfigs {
							for _, sentry := range chainConfig.sentries[j] {
								startArgs = append(startArgs, "-s", fmt.Sprintf("tcp://%s:1234", sentry.HostName()))
							}
						}

						proxy, err := horcruxProxySidecar(ctx, firstSentry, fmt.Sprintf("proxy-%d", j+1), client, network, startArgs...)
						if err != nil {
							wg.Done()
							return err
						}

						cosignerSidecars[j] = horcruxSidecarProcess{
							cosigner: cosigner,
							proxy:    proxy,
						}
					}
				}

				if err := enablePrivvalListener(ctx, logger, sentries, client); err != nil {
					wg.Done()
					return err
				}

				wg.Done()

				// wait for all cosigners to be started before continuing to start the chain.
				<-cosignersStarted

				return nil
			}
		}
	}

	go configureAndStartSidecars(ctx, t, eciesShards, cosignerSidecars, threshold, &wg, cosignersStarted, chainConfigs...)

	for i := 0; i < totalChains; i++ {
		chainWrappers[i] = &chainWrapper{
			totalValidators: validatorsPerChain,
			totalSentries:   sentriesPerValidator - 1,
			modifyGenesis:   modifyGenesisStrictUptime,
			preGenesis:      preGenesises[i],
		}
	}

	startChains(ctx, t, logger, client, network, chainWrappers...)

	chains := make([]testutil.ChainHeighter, totalChains)
	for i, cw := range chainWrappers {
		chains[i] = cw.chain
	}

	testutil.WaitForBlocks(ctx, 20, chains...)

	for i, p := range pubKeys {
		requireHealthyValidator(t, chainWrappers[i].chain.Validators[0], p.Address())
	}
}
