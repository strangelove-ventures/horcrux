package test

import (
	"context"
	"testing"

	interchaintest "github.com/strangelove-ventures/interchaintest/v7"
	"github.com/strangelove-ventures/interchaintest/v7/chain/cosmos"
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
// signer validtor.
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

	// slightly more lenient uptime requirement than modifyGenesisStrictUptime to account for
	// the time it takes to upgrade the validator, where a few missed blocks is expected.
	// allow 50% missed blocks in 10 block signed blocks window (5 missed blocks before slashing).
	modifyGenesis := modifyGenesisSlashingUptime(10, 0.5)

	startChain(ctx, t, logger, client, network, &chain, 2, 1, modifyGenesis, nil)

	// validator to upgrade to horcrux
	v := chain.Validators[0]

	err := v.StopContainer(ctx)
	require.NoError(t, err)

	pubKey, err := convertValidatorToHorcrux(ctx, logger, client, network, v, 3, 2, cosmos.ChainNodes{v}, 1)
	require.NoError(t, err)

	err = v.StartContainer(ctx)
	require.NoError(t, err)

	err = testutil.WaitForBlocks(ctx, 20, chain)
	require.NoError(t, err)

	requireHealthyValidator(t, chain.Validators[0], pubKey.Address())
}

func TestDownedSigners2of3(t *testing.T) {
	ctx := context.Background()
	chain, pubKey := startChainSingleNodeAndHorcruxThreshold(ctx, t, 2, 3, 2, 3, 3)

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

func TestDownedSigners3of5(t *testing.T) {
	ctx := context.Background()
	chain, pubKey := startChainSingleNodeAndHorcruxThreshold(ctx, t, 2, 5, 3, 3, 3)

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

func TestLeaderElection2of3(t *testing.T) {
	ctx := context.Background()
	chain, pubKey := startChainSingleNodeAndHorcruxThreshold(ctx, t, 2, 3, 2, 3, 3)

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

// tests a chain with only horcrux validators
func TestChainPureHorcrux(t *testing.T) {
	t.Parallel()
	ctx, home, pool, network := SetupTestRun(t)

	const (
		totalValidators      = 4
		signersPerValidator  = 3
		sentriesPerValidator = 2
		threshold            = 2
		sentriesPerSigner    = sentriesPerValidator
	)
	var chain *ChainType
	if false {
		// keeping this here as example of testing another chain
		chain = getSentinelChain(ctx, chainID, sentriesPerSigner, "v0.8.3")
	} else {
		chain = getSimdChain(chainID, sentriesPerSigner)
	}

	var validators []*Validator
	var startValidatorsErrGroup errgroup.Group

	var allNodes Nodes

	// start horcrux cluster for each validator
	for i := 0; i < totalValidators; i++ {
		validator, err := NewHorcruxValidator(t, pool, network, home, i,
			signersPerValidator, threshold, chain)
		require.NoError(t, err)
		validators = append(validators, validator)
		allNodes = append(allNodes, validator.Sentries[chainID]...)
		startValidatorsErrGroup.Go(func() error {
			return validator.StartHorcruxCluster(sentriesPerSigner)
		})
	}

	require.NoError(t, startValidatorsErrGroup.Wait())

	// assemble and combine gentx to get genesis file, configure peering between sentries, then start the chain
	require.NoError(t, Genesis(ctx, t, chain, []*Node{}, []*Node{}, validators))

	require.NoError(t, allNodes.WaitForHeight(5))

	var blockWaitErrGroup errgroup.Group

	// wait for all validators to sign consecutive blocks
	for _, tv := range validators {
		validator := tv
		blockWaitErrGroup.Go(func() error {
			err := validator.WaitForConsecutiveBlocks(chainID, 30)
			if err != nil {
				return err
			}
			return validator.EnsureNotSlashed(chainID)
		})
	}

	// wait for all validators to have consecutive blocks
	require.NoError(t, blockWaitErrGroup.Wait())
}

// tests running a validator across multiple chains with a single horcrux cluster
func TestMultipleChainHorcrux(t *testing.T) {
	t.Parallel()
	ctx, home, pool, network := SetupTestRun(t)

	const (
		totalValidators      = 2
		signersPerValidator  = 3
		sentriesPerValidator = 2
		threshold            = 2
		sentriesPerSigner    = sentriesPerValidator
	)
	chainID1, chainID2 := "chain-1", "chain-2"
	chain1, chain2 := getSimdChain(chainID1, sentriesPerSigner), getSimdChain(chainID2, sentriesPerSigner)

	var validators []*Validator
	var startValidatorsErrGroup errgroup.Group

	var allNodes Nodes

	// start horcrux cluster for each validator
	for i := 0; i < totalValidators; i++ {
		validator, err := NewHorcruxValidator(t, pool, network, home, i,
			signersPerValidator, threshold, chain1, chain2)
		require.NoError(t, err)
		validators = append(validators, validator)
		allNodes = append(allNodes, validator.Sentries[chainID1]...)
		allNodes = append(allNodes, validator.Sentries[chainID2]...)
		startValidatorsErrGroup.Go(func() error {
			return validator.StartHorcruxCluster(sentriesPerSigner)
		})
	}

	require.NoError(t, startValidatorsErrGroup.Wait())

	// assemble and combine gentx to get genesis file, configure peering between sentries, then start the chain
	require.NoError(t, Genesis(ctx, t, chain1, []*Node{}, []*Node{}, validators))
	require.NoError(t, Genesis(ctx, t, chain2, []*Node{}, []*Node{}, validators))

	require.NoError(t, allNodes.WaitForHeight(5))

	var blockWaitErrGroup errgroup.Group

	// wait for all validators to sign consecutive blocks on both chains
	for _, tv := range validators {
		validator := tv
		blockWaitErrGroup.Go(func() error {
			err := validator.WaitForConsecutiveBlocks(chainID1, 30)
			if err != nil {
				return err
			}
			return validator.EnsureNotSlashed(chainID1)
		})
		blockWaitErrGroup.Go(func() error {
			err := validator.WaitForConsecutiveBlocks(chainID2, 30)
			if err != nil {
				return err
			}
			return validator.EnsureNotSlashed(chainID2)
		})
	}

	// wait for all validators to have consecutive blocks
	require.NoError(t, blockWaitErrGroup.Wait())
}
