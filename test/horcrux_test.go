package test

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"golang.org/x/sync/errgroup"
)

var (
	chainID = "horcrux"
)

// Test4Of7SignerTwoSentries will spin up a chain with three single-node validators and one horcrux validator
// the horcrux validator will have seven signer nodes with a threshold of four, and two sentry nodes
// checks that no slashing occurs
func Test4Of7SignerTwoSentries(t *testing.T) {
	t.Parallel()
	ctx, home, pool, network := SetupTestRun(t)

	const totalValidators = 4
	const totalSentries = 4
	const totalSigners = 7
	const threshold = 4
	const sentriesPerSigner = 2
	chain := getSimdChain()

	// setup a horcrux validator for us
	ourValidator, err := NewHorcruxValidator(t, pool, home, chainID, 0, totalSentries, totalSigners, threshold, chain)
	require.NoError(t, err)

	// other vals are single node (non-horcrux)
	otherValidatorNodes := GetValidators(1, totalValidators-1, 1, home, chainID, chain, pool, t)

	// start our validator's horcrux cluster
	require.NoError(t, ourValidator.StartHorcruxCluster(ctx, network, sentriesPerSigner))

	// assemble and combine gentx to get genesis file, configure peering between sentries, then start the chain
	require.NoError(t, Genesis(t, ctx, network, chain, otherValidatorNodes, []*TestNode{}, []*TestValidator{ourValidator}))

	// Wait for all nodes to get to given block height
	require.NoError(t, GetAllNodes(otherValidatorNodes, ourValidator.Sentries).WaitForHeight(5))

	t.Logf("{%s} -> Checking that slashing has not occurred...", ourValidator.Name())
	require.NoError(t, ourValidator.EnsureNotSlashed())
}

// Test2Of3SignerTwoSentries will spin up a chain with three single-node validators and one horcrux validator
// the horcrux validator will have three signer nodes with a threshold of two, and two sentry nodes
// checks that no slashing occurs
func Test2Of3SignerTwoSentries(t *testing.T) {
	t.Parallel()
	ctx, home, pool, network := SetupTestRun(t)

	const totalValidators = 4
	const totalSentries = 2
	const totalSigners = 3
	const threshold = 2
	const sentriesPerSigner = 2
	chain := getSimdChain()

	// setup a horcrux validator for us
	ourValidator, err := NewHorcruxValidator(t, pool, home, chainID, 0, totalSentries, totalSigners, threshold, chain)
	require.NoError(t, err)

	// remaining validators are single-node non-horcrux
	otherValidatorNodes := GetValidators(1, totalValidators-1, 1, home, chainID, chain, pool, t)

	// start our validator's horcrux cluster
	require.NoError(t, ourValidator.StartHorcruxCluster(ctx, network, sentriesPerSigner))

	// assemble and combine gentx to get genesis file, configure peering between sentries, then start the chain
	require.NoError(t, Genesis(t, ctx, network, chain, otherValidatorNodes, []*TestNode{}, []*TestValidator{ourValidator}))

	// Wait for all nodes to get to given block height
	require.NoError(t, GetAllNodes(otherValidatorNodes, ourValidator.Sentries).WaitForHeight(5))

	t.Logf("{%s} -> Checking that slashing has not occurred...", ourValidator.Name())
	require.NoError(t, ourValidator.EnsureNotSlashed())
}

// Test2Of3SignerUniqueSentry will spin up a chain with three single-node validators and one horcrux validator
// the horcrux validator will have three signer nodes with a threshold of two, and one sentry node
// checks that no slashing occurs
func Test2Of3SignerUniqueSentry(t *testing.T) {
	t.Parallel()
	ctx, home, pool, network := SetupTestRun(t)

	const totalValidators = 4
	const totalSentries = 2
	const totalSigners = 3
	const threshold = 2
	const sentriesPerSigner = 1
	chain := getSimdChain()

	// setup a horcrux validator for us
	ourValidator, err := NewHorcruxValidator(t, pool, home, chainID, 0, totalSentries, totalSigners, threshold, chain)
	require.NoError(t, err)

	// remaining validators are single-node non-horcrux
	otherValidatorNodes := GetValidators(1, totalValidators-1, 1, home, chainID, chain, pool, t)

	// start our validator's horcrux cluster
	require.NoError(t, ourValidator.StartHorcruxCluster(ctx, network, sentriesPerSigner))

	// assemble and combine gentx to get genesis file, configure peering between sentries, then start the chain
	require.NoError(t, Genesis(t, ctx, network, chain, otherValidatorNodes, []*TestNode{}, []*TestValidator{ourValidator}))

	// Wait for all nodes to get to given block height
	require.NoError(t, GetAllNodes(otherValidatorNodes, ourValidator.Sentries).WaitForHeight(5))

	t.Logf("{%s} -> Checking that slashing has not occurred...", ourValidator.Name())
	require.NoError(t, ourValidator.EnsureNotSlashed())
}

// TestSingleSignerTwoSentries will spin up a chain with four validators & one sentry node, stop one validator & the
// sentry node, configure those two nodes to be relays for the remote signer, spin up a single remote signer, restart
// the validator/sentry node and check that no slashing occurs
func TestSingleSignerTwoSentries(t *testing.T) {
	t.Parallel()
	ctx, home, pool, network := SetupTestRun(t)

	const totalValidators = 4
	const totalSentries = 2
	const totalSigners = 1
	chain := getSimdChain()

	// get total sentries nodes for our validator
	ourValidatorNodes := GetValidators(0, 1, totalSentries, home, chainID, chain, pool, t)

	// using the first node for account and consensus key to create gentx
	ourValidatorAccountNode := ourValidatorNodes[0]

	// other vals are single node (non-horcrux)
	otherValidatorNodes := GetValidators(1, totalValidators-1, 1, home, chainID, chain, pool, t)

	// nodes that will be used for account and consensus key to create gentx
	validatorAccountNodes := GetAllNodes([]*TestNode{ourValidatorAccountNode}, otherValidatorNodes)

	// nodes that will initially be setup as simple fullnodes, then enable privval listener
	// not used for gentx tasks. In this case it is only our val's second node
	// both of ourValidatorNodes are sentries, but for initial setup only the first one is used for gentx.
	sentries := []*TestNode{ourValidatorNodes[1]}

	// initialize horcrux signer nodes for our validator
	signers := MakeTestSigners(0, totalSigners, home, pool, t)

	// assemble and combine gentx to get genesis file, configure peering between sentries, then start the chain
	require.NoError(t, Genesis(t, ctx, network, chain, validatorAccountNodes, sentries, []*TestValidator{}))

	allNodes := GetAllNodes(validatorAccountNodes, sentries)

	// Wait for all nodes to get to given block height
	require.NoError(t, allNodes.WaitForHeight(5))

	// start remote signer
	require.NoError(t, StartSingleSignerContainers(signers, ourValidatorAccountNode, ourValidatorNodes, network))

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

	require.NoError(t, ourValidatorAccountNode.CreateNodeContainer(network.ID))
	require.NoError(t, sentries[0].CreateNodeContainer(network.ID))

	require.NoError(t, ourValidatorAccountNode.StartContainer(ctx))
	require.NoError(t, sentries[0].StartContainer(ctx))

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

	const totalValidators = 4
	const totalSigners = 3
	const threshold = 2
	const sentriesPerSigner = 1
	chain := getSimdChain()

	// initially all vals are single node (non-horcrux)
	validators := GetValidators(0, totalValidators, 1, home, chainID, chain, pool, t)

	// for this test we will upgrade the first validator to horcrux
	ourValidatorNode := validators[0]

	// assemble and combine gentx to get genesis file, configure peering between sentries, then start the chain
	require.NoError(t, Genesis(t, ctx, network, chain, validators, []*TestNode{}, []*TestValidator{}))

	// Wait for all validators to get to given block height
	require.NoError(t, validators.WaitForHeight(5))

	// get the consensus key from our validator
	ourValidatorPrivValKey, err := ourValidatorNode.GetPrivVal()
	require.NoError(t, err)

	// create horcrux validator with same consensus key
	ourValidatorUpgradedToHorcrux, err := NewHorcruxValidatorWithPrivValKey(t, pool, home,
		chainID, 0, 0, totalSigners, threshold, getSimdChain(), ourValidatorPrivValKey)
	require.NoError(t, err)

	// stop our validator node before upgrading to horcrux
	t.Logf("{%s} -> Stopping Node...", ourValidatorNode.Name())
	require.NoError(t, ourValidatorNode.StopAndRemoveContainer(false))

	time.Sleep(5 * time.Second) // wait for all containers to stop

	// bring in single signer node as a sentry for horcrux
	ourValidatorUpgradedToHorcrux.Sentries = []*TestNode{ourValidatorNode}

	// modify node config to listen for private validator connections
	ourValidatorNode.SetPrivValListen(validators.PeerString())

	// remove priv_validator_key.json from our validator node
	// horcrux now holds the sharded key
	ourValidatorNode.GenNewPrivVal()

	// start our new validator
	require.NoError(t, ourValidatorUpgradedToHorcrux.StartHorcruxCluster(ctx, network, sentriesPerSigner))

	t.Logf("{%s} -> Restarting Node...", ourValidatorNode.Name())
	require.NoError(t, ourValidatorNode.CreateNodeContainer(network.ID))
	require.NoError(t, ourValidatorNode.StartContainer(ctx))

	// wait for validator to be reachable
	require.NoError(t, ourValidatorNode.GetHosts().WaitForAllToStart(t, 10))

	t.Logf("{%s} -> Checking that slashing has not occurred...", ourValidatorUpgradedToHorcrux.Name())
	require.NoError(t, ourValidatorUpgradedToHorcrux.EnsureNotSlashed())
}

func TestDownedSigners2of3(t *testing.T) {
	t.Parallel()
	ctx, home, pool, network := SetupTestRun(t)

	const totalValidators = 4
	const totalSigners = 3
	const totalSentries = 2
	const threshold = 2
	const sentriesPerSigner = 3
	chain := getSimdChain()

	// setup a horcrux validator for us
	ourValidator, err := NewHorcruxValidator(t, pool, home, chainID, 0, totalSentries, totalSigners, threshold, chain)
	require.NoError(t, err)

	// remaining validators are single-node non-horcrux
	otherValidatorNodes := GetValidators(1, totalValidators-1, 1, home, chainID, chain, pool, t)

	// start our validator's horcrux cluster
	require.NoError(t, ourValidator.StartHorcruxCluster(ctx, network, sentriesPerSigner))

	// assemble and combine gentx to get genesis file, configure peering between sentries, then start the chain
	require.NoError(t, Genesis(t, ctx, network, chain, otherValidatorNodes, []*TestNode{}, []*TestValidator{ourValidator}))

	// Wait for all nodes to get to given block height
	require.NoError(t, GetAllNodes(otherValidatorNodes, ourValidator.Sentries).WaitForHeight(5))

	t.Logf("{%s} -> Checking that slashing has not occurred...", ourValidator.Name())
	require.NoError(t, ourValidator.EnsureNotSlashed())

	// Test taking down each node in the signer cluster for a period of time
	for _, signer := range ourValidator.Signers {
		t.Logf("{%s} -> Stopping signer...", signer.Name())
		require.NoError(t, signer.StopAndRemoveContainer(false))

		t.Logf("{%s} -> Waiting until cluster recovers from taking down signer {%s}", ourValidator.Name(), signer.Name())
		require.NoError(t, ourValidator.WaitForConsecutiveBlocks(10))

		t.Logf("{%s} -> Restarting signer...", signer.Name())
		require.NoError(t, signer.CreateCosignerContainer(network.ID))
		require.NoError(t, signer.StartContainer())
		require.NoError(t, signer.GetHosts().WaitForAllToStart(t, 10)) // Wait to ensure signer is back up
		require.NoError(t, ourValidator.WaitForConsecutiveBlocks(10))
	}
	t.Logf("{%s} -> Checking that slashing has not occurred...", ourValidator.Name())
	require.NoError(t, ourValidator.EnsureNotSlashed())
}

func TestDownedSigners3of5(t *testing.T) {
	t.Parallel()
	ctx, home, pool, network := SetupTestRun(t)

	const totalValidators = 4
	const totalSigners = 5
	const totalSentries = 4
	const threshold = 3
	const sentriesPerSigner = 5
	chain := getSimdChain()

	// setup a horcrux validator for us
	ourValidator, err := NewHorcruxValidator(t, pool, home, chainID, 0, totalSentries, totalSigners, threshold, chain)
	require.NoError(t, err)

	// remaining validators are single-node non-horcrux
	otherValidatorNodes := GetValidators(1, totalValidators-1, 1, home, chainID, chain, pool, t)

	// start our validator's horcrux cluster
	require.NoError(t, ourValidator.StartHorcruxCluster(ctx, network, sentriesPerSigner))

	// assemble and combine gentx to get genesis file, configure peering between sentries, then start the chain
	require.NoError(t, Genesis(t, ctx, network, chain, otherValidatorNodes, []*TestNode{}, []*TestValidator{ourValidator}))

	// Wait for all nodes to get to given block height
	require.NoError(t, GetAllNodes(otherValidatorNodes, ourValidator.Sentries).WaitForHeight(5))

	t.Logf("{%s} -> Checking that slashing has not occurred...", ourValidator.Name())
	require.NoError(t, ourValidator.EnsureNotSlashed())

	// Test taking down 2 nodes at a time in the signer cluster for a period of time
	for i := 0; i < len(ourValidator.Signers); i++ {
		signer1 := ourValidator.Signers[i]
		var signer2 *TestSigner
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
		require.NoError(t, ourValidator.WaitForConsecutiveBlocks(10))

		t.Logf("{%s} -> Restarting signer...", signer1.Name())
		require.NoError(t, signer1.CreateCosignerContainer(network.ID))
		require.NoError(t, signer1.StartContainer())
		require.NoError(t, signer1.GetHosts().WaitForAllToStart(t, 10)) // Wait to ensure signer is back up
		require.NoError(t, ourValidator.WaitForConsecutiveBlocks(10))
	}
	t.Logf("{%s} -> Checking that slashing has not occurred...", ourValidator.Name())
	require.NoError(t, ourValidator.EnsureNotSlashed())
}

// tests a chain with only horcrux validators
func TestChainPureHorcrux(t *testing.T) {
	t.Parallel()
	ctx, home, pool, network := SetupTestRun(t)

	const totalValidators = 4
	const signersPerValidator = 3
	const sentriesPerValidator = 2
	const threshold = 2
	const sentriesPerSigner = sentriesPerValidator
	var chain *ChainType
	if false {
		// keeping this here as example of testing another chain
		chain = getSentinelChain(ctx, "v0.8.3")
	} else {
		chain = getSimdChain()
	}

	var validators []*TestValidator
	var startValidatorsErrGroup errgroup.Group

	var allNodes TestNodes

	// start horcrux cluster for each validator
	for i := 0; i < totalValidators; i++ {
		validator, err := NewHorcruxValidator(t, pool, home, chainID, i,
			sentriesPerValidator, signersPerValidator, threshold, chain)
		require.NoError(t, err)
		validators = append(validators, validator)
		allNodes = append(allNodes, validator.Sentries...)
		startValidatorsErrGroup.Go(func() error {
			return validator.StartHorcruxCluster(ctx, network, sentriesPerSigner)
		})
	}

	require.NoError(t, startValidatorsErrGroup.Wait())

	// assemble and combine gentx to get genesis file, configure peering between sentries, then start the chain
	require.NoError(t, Genesis(t, ctx, network, chain, []*TestNode{}, []*TestNode{}, validators))

	require.NoError(t, allNodes.WaitForHeight(5))

	var blockWaitErrGroup errgroup.Group

	// wait for all validators to sign consecutive blocks
	for _, tv := range validators {
		validator := tv
		blockWaitErrGroup.Go(func() error {
			err := validator.WaitForConsecutiveBlocks(30)
			if err != nil {
				return err
			}
			return validator.EnsureNotSlashed()
		})
	}

	// wait for all validators to have consecutive blocks
	require.NoError(t, blockWaitErrGroup.Wait())
}
