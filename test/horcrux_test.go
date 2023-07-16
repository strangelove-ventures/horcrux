package test

import (
	"context"
	"fmt"
	"testing"

	"github.com/cometbft/cometbft/crypto"
	"github.com/strangelove-ventures/horcrux/signer"
	interchaintest "github.com/strangelove-ventures/interchaintest/v7"
	"github.com/strangelove-ventures/interchaintest/v7/chain/cosmos"
	"github.com/strangelove-ventures/interchaintest/v7/ibc"
	"github.com/strangelove-ventures/interchaintest/v7/testutil"
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

	var chain *cosmos.CosmosChain

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

	startChains(ctx, t, logger, client, network, chainWrapper{
		chain:           &chain,
		totalValidators: totalValidators,
		modifyGenesis:   modifyGenesis,
	})

	// validator to upgrade to horcrux
	v := chain.Validators[0]

	err := v.StopContainer(ctx)
	require.NoError(t, err)

	pubKey, err := convertValidatorToHorcrux(ctx, logger, client, network, v, totalSigners, threshold, cosmos.ChainNodes{v}, sentriesPerSigner)
	require.NoError(t, err)

	err = v.StartContainer(ctx)
	require.NoError(t, err)

	err = testutil.WaitForBlocks(ctx, 20, chain)
	require.NoError(t, err)

	requireHealthyValidator(t, chain.Validators[0], pubKey.Address())
}

// TestDownedSigners2of3 tests taking down 2 nodes at a time in the 2/3 threshold horcrux cluster for a period of time.

func TestDownedSigners2of3(t *testing.T) {
	ctx := context.Background()

	const (
		totalValidators   = 2
		totalSigners      = 3
		threshold         = 2
		totalSentries     = 3
		sentriesPerSigner = 3
	)

	chain, pubKey := startChainSingleNodeAndHorcruxThreshold(
		ctx, t, totalValidators, totalSigners, threshold, totalSentries, sentriesPerSigner,
	)

	ourValidator := chain.Validators[0]
	requireHealthyValidator(t, ourValidator, pubKey.Address())

	cosigners := ourValidator.Sidecars

	// Test taking down each node in the signer cluster for a period of time
	for _, cosigner := range cosigners {
		t.Logf("{%s} -> Stopping signer...", cosigner.Name())
		require.NoError(t, cosigner.StopContainer(ctx))

		t.Logf("{%s} -> Waiting for blocks after stopping cosigner {%s}", ourValidator.Name(), cosigner.Name())
		require.NoError(t, testutil.WaitForBlocks(ctx, 5, chain))

		requireHealthyValidator(t, ourValidator, pubKey.Address())

		t.Logf("{%s} -> Restarting signer...", cosigner.Name())
		require.NoError(t, cosigner.StartContainer(ctx))

		t.Logf("{%s} -> Waiting for blocks after restarting cosigner {%s}", ourValidator.Name(), cosigner.Name())
		require.NoError(t, testutil.WaitForBlocks(ctx, 5, chain))

		requireHealthyValidator(t, ourValidator, pubKey.Address())
	}
}

// TestDownedSigners3of5 tests taking down 2 nodes at a time in the 3/5 threshold horcrux cluster for a period of time.
func TestDownedSigners3of5(t *testing.T) {
	ctx := context.Background()

	const (
		totalValidators   = 2
		totalSigners      = 5
		threshold         = 3
		totalSentries     = 3
		sentriesPerSigner = 3
	)

	chain, pubKey := startChainSingleNodeAndHorcruxThreshold(
		ctx, t, totalValidators, totalSigners, threshold, totalSentries, sentriesPerSigner,
	)

	ourValidator := chain.Validators[0]
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
		require.NoError(t, testutil.WaitForBlocks(ctx, 5, chain))

		requireHealthyValidator(t, ourValidator, pubKey.Address())

		t.Logf("{%s} -> Restarting cosigner...", cosigner1.Name())
		require.NoError(t, cosigner1.StartContainer(ctx))
		require.NoError(t, testutil.WaitForBlocks(ctx, 5, chain))

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

	chain, pubKey := startChainSingleNodeAndHorcruxThreshold(
		ctx, t, totalValidators, totalSigners, threshold, totalSentries, sentriesPerSigner,
	)

	ourValidator := chain.Validators[0]
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
					return pollForLeader(ctx, t, s, cosigner.Name()+":"+signerPort)
				})
			}
			if err := eg.Wait(); err == nil {
				break
			}

			// electing a specific leader can fail, but this is okay as long as all nodes agree on one leader.
			// will retry electing the specific leader in the next iteration.
			var commonLeader string
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

		require.NoError(t, testutil.WaitForBlocks(ctx, 5, chain))

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

	var chain *cosmos.CosmosChain
	pubKeys := make([]crypto.PubKey, totalValidators)

	startChains(
		ctx, t, logger, client, network, chainWrapper{
			chain:           &chain,
			totalValidators: totalValidators,
			totalSentries:   1 + totalValidators*(sentriesPerValidator-1),
			modifyGenesis:   modifyGenesisStrictUptime,
			preGenesis:      preGenesisAllHorcruxThreshold(ctx, logger, client, network, signersPerValidator, threshold, sentriesPerValidator, sentriesPerSigner, &chain, pubKeys),
		},
	)

	err := testutil.WaitForBlocks(ctx, 20, chain)
	require.NoError(t, err)

	for _, p := range pubKeys {
		requireHealthyValidator(t, chain.Validators[0], p.Address())
	}
}

// TestMultipleChainHorcrux tests running a validator across multiple chains with a single horcrux cluster.
func TestMultipleChainHorcrux(t *testing.T) {
	ctx := context.Background()
	client, network := interchaintest.DockerSetup(t)
	logger := zaptest.NewLogger(t)

	var chain1, chain2 *cosmos.CosmosChain
	pubKeys := make([]crypto.PubKey, 2)

	oneDoneChan := make(chan struct{}, 1)

	const (
		totalSigners      = 3
		threshold         = 2
		sentriesPerSigner = 1
	)

	eciesShards, err := signer.CreateCosignerECIESShards(totalSigners)
	require.NoError(t, err)

	cosignerConfig := make([]signer.Config, totalSigners)

	var chain1Shards []signer.CosignerEd25519Key

	preGenesis1 := func(cc ibc.ChainConfig) error {
		validator := (*chain1).Validators[0]

		sentries := append(cosmos.ChainNodes{validator}, (*chain1).FullNodes...)

		sentriesForCosigners := getSentriesForCosignerConnection(sentries, totalSigners, sentriesPerSigner)

		ed25519Shards, pvPubKey, err := getShardedPrivvalKey(ctx, validator, threshold, uint8(totalSigners))
		if err != nil {
			return err
		}

		chain1Shards = ed25519Shards

		cosigners := make(signer.CosignersConfig, totalSigners)

		for i := 0; i < totalSigners; i++ {
			_, err := horcruxSidecar(ctx, validator, fmt.Sprintf("cosigner-%d", i+1), client, network)
			if err != nil {
				return err
			}

			cosigners[i] = signer.CosignerConfig{
				ShardID: i + 1,
				P2PAddr: fmt.Sprintf("tcp://%s:%s", validator.Sidecars[i].HostName(), signerPort),
			}
		}

		for i := 0; i < totalSigners; i++ {
			sentriesForCosigner := sentriesForCosigners[i]
			chainNodes := make(signer.ChainNodes, len(sentriesForCosigner))
			for i, sentry := range sentriesForCosigner {
				chainNodes[i] = signer.ChainNode{
					PrivValAddr: fmt.Sprintf("tcp://%s:1234", sentry.HostName()),
				}
			}

			cosignerConfig[i] = signer.Config{
				SignMode: signer.SignModeThreshold,
				ThresholdModeConfig: &signer.ThresholdModeConfig{
					Threshold:   int(threshold),
					Cosigners:   cosigners,
					GRPCTimeout: "1500ms",
					RaftTimeout: "1500ms",
				},
				ChainNodes: chainNodes,
			}
		}

		if err := enablePrivvalListener(ctx, logger, sentries, client); err != nil {
			return err
		}

		pubKeys[0] = pvPubKey

		close(oneDoneChan)

		return nil
	}

	preGenesis2 := func(cc ibc.ChainConfig) error {
		<-oneDoneChan

		validator := (*chain2).Validators[0]
		chain1Validator := (*chain1).Validators[0]

		sentries := append(cosmos.ChainNodes{validator}, (*chain2).FullNodes...)

		sentriesForCosigners := getSentriesForCosignerConnection(sentries, totalSigners, sentriesPerSigner)

		ed25519Shards, pvPubKey, err := getShardedPrivvalKey(ctx, validator, threshold, uint8(totalSigners))
		if err != nil {
			return err
		}

		for i := 0; i < totalSigners; i++ {
			cosigner := chain1Validator.Sidecars[i]

			sentriesForCosigner := sentriesForCosigners[i]
			chainNodes := make(signer.ChainNodes, len(sentriesForCosigner))
			for i, sentry := range sentriesForCosigner {
				chainNodes[i] = signer.ChainNode{
					PrivValAddr: fmt.Sprintf("tcp://%s:1234", sentry.HostName()),
				}
			}

			cosignerConfig[i].ChainNodes = append(cosignerConfig[i].ChainNodes, chainNodes...)

			if err := writeConfigAndKeysThreshold(ctx, cosigner, cosignerConfig[i], eciesShards[i],
				chainEd25519Key{
					chainID: chain1Validator.Chain.Config().ChainID,
					key:     chain1Shards[i],
				},
				chainEd25519Key{
					chainID: validator.Chain.Config().ChainID,
					key:     ed25519Shards[i],
				},
			); err != nil {
				return err
			}
		}

		if err := enablePrivvalListener(ctx, logger, sentries, client); err != nil {
			return err
		}

		pubKeys[1] = pvPubKey

		return nil
	}

	startChains(ctx, t, logger, client, network,
		chainWrapper{
			chain:           &chain1,
			totalValidators: 2,
			totalSentries:   2,
			modifyGenesis:   modifyGenesisStrictUptime,
			preGenesis:      preGenesis1,
		},
		chainWrapper{
			chain:           &chain2,
			totalValidators: 2,
			totalSentries:   2,
			modifyGenesis:   modifyGenesisStrictUptime,
			preGenesis:      preGenesis2,
		},
	)

	testutil.WaitForBlocks(ctx, 20, chain1, chain2)

	requireHealthyValidator(t, chain1.Validators[0], pubKeys[0].Address())
	requireHealthyValidator(t, chain2.Validators[0], pubKeys[1].Address())
}
