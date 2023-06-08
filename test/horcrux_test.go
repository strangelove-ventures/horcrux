package test

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"golang.org/x/sync/errgroup"
)

const (
	chainID                    = "horcrux"
	maxSpecificElectionRetries = 3
)

func testChainSingleNodeAndHorcrux(
	t *testing.T,
	totalValidators int, // total number of validators on chain (one horcrux + single node for the rest)
	totalSigners int, // total number of signers for the single horcrux validator
	threshold uint8, // key shard threshold, and therefore how many horcrux signers must participate to sign a block
	totalSentries int, // number of sentry nodes for the single horcrux validator
	sentriesPerSigner int, // how many sentries should each horcrux signer connect to (min: 1, max: totalSentries)
) {
	ctx, home, pool, network := SetupTestRun(t)

	chain := getSimdChain(chainID, totalSentries)

	// setup a horcrux validator for us
	ourValidator, err := NewHorcruxValidator(t, pool, network, home, 0, totalSigners, threshold, chain)
	require.NoError(t, err)

	// other vals are single node (non-horcrux)
	chain.NumSentries = 1
	otherValidatorNodes := GetValidators(1, totalValidators-1, home, chain, pool, network, t)

	// start our validator's horcrux cluster
	require.NoError(t, ourValidator.StartHorcruxCluster(sentriesPerSigner))

	// assemble and combine gentx to get genesis file, configure peering between sentries, then start the chain
	require.NoError(t, Genesis(ctx, t, chain, otherValidatorNodes, []*Node{}, []*Validator{ourValidator}))

	// Wait for all nodes to get to given block height
	require.NoError(t, GetAllNodes(otherValidatorNodes, ourValidator.Sentries[chainID]).WaitForHeight(5))

	//Get Metrics in separate go routine
	go ourValidator.CaptureCosignerMetrics(ctx)

	require.NoError(t, ourValidator.WaitForConsecutiveBlocks(chainID, 10))

	t.Logf("{%s} -> Checking that slashing has not occurred...", ourValidator.Name())

	require.NoError(t, ourValidator.EnsureNotSlashed(chainID))
}

// Test4Of7SignerTwoSentries will spin up a chain with three single-node validators and one horcrux validator
// the horcrux validator will have seven signer nodes with a threshold of four, and two sentry nodes
// checks that no slashing occurs
func Test4Of7SignerTwoSentries(t *testing.T) {
	t.Parallel()
	testChainSingleNodeAndHorcrux(t, 4, 7, 4, 2, 2)
}

// Test2Of3SignerTwoSentries will spin up a chain with three single-node validators and one horcrux validator
// the horcrux validator will have three signer nodes with a threshold of two, and two sentry nodes
// checks that no slashing occurs
func Test2Of3SignerTwoSentries(t *testing.T) {
	t.Parallel()
	testChainSingleNodeAndHorcrux(t, 4, 3, 2, 2, 2)
}

// Test2Of3SignerUniqueSentry will spin up a chain with three single-node validators and one horcrux validator
// the horcrux validator will have three signer nodes with a threshold of two, and one sentry node
// checks that no slashing occurs
func Test2Of3SignerUniqueSentry(t *testing.T) {
	t.Parallel()
	testChainSingleNodeAndHorcrux(t, 4, 3, 2, 1, 1)
}

//

// TestSingleSignerTwoSentries will spin up a chain with four validators & one sentry node, stop one validator & the
// sentry node, configure those two nodes to be relays for the remote signer, spin up a single remote signer, restart
// the validator/sentry node and check that no slashing occurs
func TestSingleSignerTwoSentries(t *testing.T) {
	t.Parallel()
	ctx, home, pool, network := SetupTestRun(t)

	const (
		totalValidators = 4
		totalSentries   = 2
		totalSigners    = 1
	)
	chain := getSimdChain(chainID, totalSentries)

	// get total sentries nodes for our validator
	ourValidatorNodes := GetValidators(0, 1, home, chain, pool, network, t)

	// using the first node for account and consensus key to create gentx
	ourValidatorAccountNode := ourValidatorNodes[0]

	// other vals are single node (non-horcrux)
	chain.NumSentries = 1
	otherValidatorNodes := GetValidators(1, totalValidators-1, home, chain, pool, network, t)

	// nodes that will be used for account and consensus key to create gentx
	validatorAccountNodes := GetAllNodes([]*Node{ourValidatorAccountNode}, otherValidatorNodes)

	// nodes that will initially be setup as simple fullnodes, then enable privval listener
	// not used for gentx tasks. In this case it is only our val's second node
	// both of ourValidatorNodes are sentries, but for initial setup only the first one is used for gentx.
	sentries := []*Node{ourValidatorNodes[1]}

	// initialize horcrux signer nodes for our validator
	signers := MakeSigners(0, totalSigners, home, pool, network, t)

	// assemble and combine gentx to get genesis file, configure peering between sentries, then start the chain
	require.NoError(t, Genesis(ctx, t, chain, validatorAccountNodes, sentries, []*Validator{}))

	allNodes := GetAllNodes(validatorAccountNodes, sentries)

	// Wait for all nodes to get to given block height
	require.NoError(t, allNodes.WaitForHeight(5))

	// start remote signer
	require.NoError(t, StartSingleSignerContainers(signers, ourValidatorAccountNode, ourValidatorNodes))

	// Stop the validator node and sentry node before upgrading to horcrux
	t.Logf("{%s} -> Stopping Node...", ourValidatorAccountNode.Name())
	require.NoError(t, ourValidatorAccountNode.StopAndRemoveContainer(false))

	t.Logf("{%s} -> Stopping Node...", sentries[0].Name())
	require.NoError(t, sentries[0].StopAndRemoveContainer(false))

	time.Sleep(5 * time.Second) // wait for all containers to stop

	// wait for all signers to be reachable on port 2222
	require.NoError(t, signers.GetHosts().WaitForAllToStart(t, 10))

	// modify node config to listen for private validator connections
	ourValidatorAccountNode.SetPrivValListen(allNodes.PeerString())
	sentries[0].SetPrivValListen(allNodes.PeerString())

	// restart node and ensure that signer cluster is connected by
	// checking if the node continues to miss blocks or is slashed
	t.Logf("{%s} -> Restarting Node...", ourValidatorAccountNode.Name())
	t.Logf("{%s} -> Restarting Node...", sentries[0].Name())

	require.NoError(t, ourValidatorAccountNode.Start(ctx, nil))
	require.NoError(t, sentries[0].Start(ctx, nil))

	// wait for our validator and all sentries to be reachable
	hosts := ourValidatorAccountNode.GetHosts()
	hosts = append(hosts, sentries[0].GetHosts()...)
	require.NoError(t, hosts.WaitForAllToStart(t, 10))

	t.Logf("{%s} -> Checking that slashing has not occurred...", ourValidatorAccountNode.Name())
	ourPrivVal, err := ourValidatorAccountNode.GetPrivVal()
	require.NoError(t, err)

	require.NoError(t, ourValidatorAccountNode.EnsureNotSlashed(ourPrivVal.PubKey.Address()))
}

// TestUpgradeValidatorToHorcrux will spin up a chain with four validators, stop one validator, configure that validator
// to be a relay for the remote signer cluster, spin up a 2/3 threshold signer cluster, restart the validator and check
// that no slashing occurs
func TestUpgradeValidatorToHorcrux(t *testing.T) {
	t.Parallel()
	ctx, home, pool, network := SetupTestRun(t)

	const (
		totalValidators   = 4
		totalSigners      = 3
		threshold         = 2
		sentriesPerSigner = 1
	)
	chain := getSimdChain(chainID, sentriesPerSigner)

	// initially all vals are single node (non-horcrux)
	validators := GetValidators(0, totalValidators, home, chain, pool, network, t)

	// for this test we will upgrade the first validator to horcrux
	ourValidatorNode := validators[0]

	// assemble and combine gentx to get genesis file, configure peering between sentries, then start the chain
	require.NoError(t, Genesis(ctx, t, chain, validators, []*Node{}, []*Validator{}))

	// Wait for all validators to get to given block height
	require.NoError(t, validators.WaitForHeight(5))

	// get the consensus key from our validator
	ourValidatorPrivValKey, err := ourValidatorNode.GetPrivVal()
	require.NoError(t, err)

	// create horcrux validator with same consensus key
	ourValidatorUpgradedToHorcrux, err := NewHorcruxValidatorWithPrivValKey(t, pool, network, home,
		0, 0, totalSigners, threshold, chain, ourValidatorPrivValKey)
	require.NoError(t, err)

	// stop our validator node before upgrading to horcrux
	t.Logf("{%s} -> Stopping Node...", ourValidatorNode.Name())
	require.NoError(t, ourValidatorNode.StopAndRemoveContainer(false))

	time.Sleep(5 * time.Second) // wait for all containers to stop

	// bring in single signer node as a sentry for horcrux
	ourValidatorUpgradedToHorcrux.Sentries[chainID] = []*Node{ourValidatorNode}

	// modify node config to listen for private validator connections
	ourValidatorNode.SetPrivValListen(validators.PeerString())

	// remove priv_validator_key.json from our validator node
	// horcrux now holds the sharded key
	ourValidatorNode.GenNewPrivVal()

	// start our new validator
	require.NoError(t, ourValidatorUpgradedToHorcrux.StartHorcruxCluster(sentriesPerSigner))

	t.Logf("{%s} -> Restarting Node...", ourValidatorNode.Name())
	require.NoError(t, ourValidatorNode.Start(ctx, nil))

	// wait for validator to be reachable
	require.NoError(t, ourValidatorNode.GetHosts().WaitForAllToStart(t, 10))

	t.Logf("{%s} -> Checking that slashing has not occurred...", ourValidatorUpgradedToHorcrux.Name())
	require.NoError(t, ourValidatorUpgradedToHorcrux.EnsureNotSlashed(chainID))
}

func TestDownedSigners2of3(t *testing.T) {
	t.Parallel()
	ctx, home, pool, network := SetupTestRun(t)

	const (
		totalValidators   = 4
		totalSigners      = 3
		threshold         = 2
		sentriesPerSigner = 3
	)
	chain := getSimdChain(chainID, sentriesPerSigner)

	// setup a horcrux validator for us
	ourValidator, err := NewHorcruxValidator(t, pool, network, home,
		0, totalSigners, threshold, chain)
	require.NoError(t, err)

	// remaining validators are single-node non-horcrux
	chain.NumSentries = 1
	otherValidatorNodes := GetValidators(1, totalValidators-1, home, chain, pool, network, t)

	// start our validator's horcrux cluster
	require.NoError(t, ourValidator.StartHorcruxCluster(sentriesPerSigner))

	// assemble and combine gentx to get genesis file, configure peering between sentries, then start the chain
	require.NoError(t, Genesis(ctx, t, chain, otherValidatorNodes, []*Node{}, []*Validator{ourValidator}))

	// Wait for all nodes to get to given block height
	require.NoError(t, GetAllNodes(otherValidatorNodes, ourValidator.Sentries[chainID]).WaitForHeight(5))

	// Test taking down each node in the signer cluster for a period of time
	for _, signer := range ourValidator.Signers {
		t.Logf("{%s} -> Stopping signer...", signer.Name())
		require.NoError(t, signer.StopAndRemoveContainer(false))

		t.Logf("{%s} -> Waiting until cluster recovers from taking down signer {%s}", ourValidator.Name(), signer.Name())
		require.NoError(t, ourValidator.WaitForConsecutiveBlocks(chainID, 10))

		t.Logf("{%s} -> Restarting signer...", signer.Name())
		require.NoError(t, signer.CreateCosignerContainer())
		require.NoError(t, signer.StartContainer())
		require.NoError(t, signer.GetHosts().WaitForAllToStart(t, 10)) // Wait to ensure signer is back up
		require.NoError(t, ourValidator.WaitForConsecutiveBlocks(chainID, 10))
	}
	t.Logf("{%s} -> Checking that slashing has not occurred...", ourValidator.Name())
	require.NoError(t, ourValidator.EnsureNotSlashed(chainID))
}

func TestLeaderElection2of3(t *testing.T) {
	t.Parallel()
	ctx, home, pool, network := SetupTestRun(t)

	const (
		totalValidators   = 4
		totalSigners      = 3
		threshold         = 2
		totalSentries     = 3
		sentriesPerSigner = 1
	)
	chain := getSimdChain(chainID, totalSentries)

	// setup a horcrux validator for us
	ourValidator, err := NewHorcruxValidator(t, pool, network, home,
		0, totalSigners, threshold, chain)
	require.NoError(t, err)

	// remaining validators are single-node non-horcrux
	chain.NumSentries = 1
	otherValidatorNodes := GetValidators(1, totalValidators-1, home, chain, pool, network, t)

	// start our validator's horcrux cluster
	require.NoError(t, ourValidator.StartHorcruxCluster(sentriesPerSigner))

	// assemble and combine gentx to get genesis file, configure peering between sentries, then start the chain
	require.NoError(t, Genesis(ctx, t, chain, otherValidatorNodes, []*Node{}, []*Validator{ourValidator}))

	// Wait for all nodes to get to given block height
	require.NoError(t, GetAllNodes(otherValidatorNodes, ourValidator.Sentries[chainID]).WaitForHeight(5))

	// Test electing each node in the signer cluster for a period of time
	for _, signer := range ourValidator.Signers {
		var eg errgroup.Group

		for i := 0; i < maxSpecificElectionRetries; i++ {
			t.Logf("{%s} -> Electing leader...", signer.Name())
			err := signer.TransferLeadership(ctx, signer.Index)
			require.NoError(t, err, "failed to transfer leadership to %d", signer.Index)

			t.Logf("{%s} -> Waiting for signed blocks with signer as leader {%s}", ourValidator.Name(), signer.Name())

			// Make sure all cosigners have the same leader
			for _, s := range ourValidator.Signers {
				s := s
				eg.Go(func() error {
					return s.PollForLeader(ctx, signer.Name()+":"+signerPort)
				})
			}
			if err := eg.Wait(); err == nil {
				break
			}

			// electing a specific leader can fail, but this is okay as long as all nodes agree on one leader.
			// will retry electing the specific leader in the next iteration.
			var commonLeader string
			for i, s := range ourValidator.Signers {
				leader, err := s.GetLeader(ctx)
				require.NoErrorf(t, err, "failed to get leader from signer: %s", s.Name())
				if i == 0 {
					commonLeader = leader
					continue
				}
				require.Equal(t, commonLeader, leader, "leader is not the same on all signers, mismatch on %s", s.Name())
			}
		}

		require.NoError(t, ourValidator.WaitForConsecutiveBlocks(chainID, 8))
	}
	t.Logf("{%s} -> Checking that slashing has not occurred...", ourValidator.Name())
	require.NoError(t, ourValidator.EnsureNotSlashed(chainID))
}

func TestDownedSigners3of5(t *testing.T) {
	t.Parallel()
	ctx, home, pool, network := SetupTestRun(t)

	const (
		totalValidators   = 4
		totalSigners      = 5
		threshold         = 3
		totalSentries     = 2
		sentriesPerSigner = 1
	)
	chain := getSimdChain(chainID, totalSentries)

	// setup a horcrux validator for us
	ourValidator, err := NewHorcruxValidator(t, pool, network, home,
		0, totalSigners, threshold, chain)
	require.NoError(t, err)

	// remaining validators are single-node non-horcrux
	chain.NumSentries = 1
	otherValidatorNodes := GetValidators(1, totalValidators-1, home, chain, pool, network, t)

	// start our validator's horcrux cluster
	require.NoError(t, ourValidator.StartHorcruxCluster(sentriesPerSigner))

	// assemble and combine gentx to get genesis file, configure peering between sentries, then start the chain
	require.NoError(t, Genesis(ctx, t, chain, otherValidatorNodes, []*Node{}, []*Validator{ourValidator}))

	// Wait for all nodes to get to given block height
	require.NoError(t, GetAllNodes(otherValidatorNodes, ourValidator.Sentries[chainID]).WaitForHeight(5))

	// Test taking down 2 nodes at a time in the signer cluster for a period of time
	for i := 0; i < len(ourValidator.Signers); i++ {
		signer1 := ourValidator.Signers[i]
		var signer2 *Signer
		if i < len(ourValidator.Signers)-1 {
			signer2 = ourValidator.Signers[i+1]
		} else {
			signer2 = ourValidator.Signers[0]
		}
		if i == 0 {
			t.Logf("{%s} -> Stopping signer...", signer1.Name())
			require.NoError(t, signer1.StopAndRemoveContainer(false))
			t.Logf("{%s} -> Stopping signer...", signer2.Name())
			require.NoError(t, signer2.StopAndRemoveContainer(false))
			t.Logf("{%s} -> Waiting until cluster recovers from taking down signer {%s}", ourValidator.Name(), signer1.Name())
		} else {
			t.Logf("{%s} -> Stopping signer...", signer2.Name())
			require.NoError(t, signer2.StopAndRemoveContainer(false))
		}

		t.Logf("{%s} -> Waiting until cluster recovers from taking down signer {%s}", ourValidator.Name(), signer2.Name())
		require.NoError(t, ourValidator.WaitForConsecutiveBlocks(chainID, 10))

		t.Logf("{%s} -> Restarting signer...", signer1.Name())
		require.NoError(t, signer1.CreateCosignerContainer())
		require.NoError(t, signer1.StartContainer())
		require.NoError(t, signer1.GetHosts().WaitForAllToStart(t, 10)) // Wait to ensure signer is back up
		require.NoError(t, ourValidator.WaitForConsecutiveBlocks(chainID, 10))
	}
	t.Logf("{%s} -> Checking that slashing has not occurred...", ourValidator.Name())
	require.NoError(t, ourValidator.EnsureNotSlashed(chainID))
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
