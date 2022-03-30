package test

import (
	"testing"
	"time"

	"github.com/ory/dockertest"
	"github.com/ory/dockertest/docker"
	"github.com/stretchr/testify/require"
	"golang.org/x/sync/errgroup"
)

var (
	chainID = "horcrux"
)

func TestBuildSignerContainer(t *testing.T) {
	// NOTE: this test isn't skipped because we are debbuging it in CIs
	t.Skip()
	pool, err := dockertest.NewPool("")
	require.NoError(t, err)
	require.NoError(t, BuildTestSignerImage(pool))
}

// Test4Of7SignerTwoSentries will spin up a chain with three single-node validators and one horcrux validator
// the horcrux validator will have seven signer nodes with a threshold of four, and two sentry nodes
// checks that no slashing occurs
func Test4Of7SignerTwoSentries(t *testing.T) {
	t.Parallel()
	const totalValidators = 4
	const totalSentries = 4
	const totalSigners = 7
	const threshold = 4
	const sentriesPerSigner = 2
	chain := getSimdChain()

	ctx, home, pool, network := SetupTestRun(t)

	// set the test cleanup function
	t.Cleanup(Cleanup(pool, t.Name(), home))

	// build the horcrux image
	require.NoError(t, BuildTestSignerImage(pool))

	// setup a horcrux validator for us
	ourValidator := NewHorcruxValidator(t, pool, home, chainID, 0, totalSentries, totalSigners, threshold, chain)

	// remaining validators are single-node non-horcrux
	var otherValidatorNodes TestNodes
	for i := 1; i < totalValidators; i++ {
		otherValidatorNodes = append(otherValidatorNodes, MakeTestNodes(i, 1, home, chainID, chain, pool, t)...)
	}

	// start our validator's horcrux cluster
	require.NoError(t, ourValidator.StartHorcruxCluster(ctx, network, sentriesPerSigner))

	// assemble and combine gentx to get genesis file, configure peering between sentries, then start the chain
	Genesis(t, ctx, network, otherValidatorNodes, []*TestNode{}, []*TestValidator{ourValidator})

	// get slice of all nodes so we can wait for them all
	var allNodes TestNodes
	allNodes = append(allNodes, otherValidatorNodes...)
	allNodes = append(allNodes, ourValidator.Sentries...)

	// Wait for all nodes to get to given block height
	allNodes.WaitForHeight(5)

	t.Logf("{%s} -> Checking that slashing has not occurred...", ourValidator.Name())
	require.NoError(t, ourValidator.EnsureNotSlashed())
}

// Test2Of3SignerTwoSentries will spin up a chain with three single-node validators and one horcrux validator
// the horcrux validator will have three signer nodes with a threshold of two, and two sentry nodes
// checks that no slashing occurs
func Test2Of3SignerTwoSentries(t *testing.T) {
	t.Parallel()

	const totalValidators = 4
	const totalSentries = 2
	const totalSigners = 3
	const threshold = 2
	const sentriesPerSigner = 2
	chain := getSimdChain()

	ctx, home, pool, network := SetupTestRun(t)

	// set the test cleanup function
	t.Cleanup(Cleanup(pool, t.Name(), home))

	// build the horcrux image
	require.NoError(t, BuildTestSignerImage(pool))

	// setup a horcrux validator for us
	ourValidator := NewHorcruxValidator(t, pool, home, chainID, 0, totalSentries, totalSigners, threshold, chain)

	// remaining validators are single-node non-horcrux
	otherValidatorNodes := GetValidators(1, totalValidators-1, 1, home, chainID, chain, pool, t)

	// start our validator's horcrux cluster
	require.NoError(t, ourValidator.StartHorcruxCluster(ctx, network, sentriesPerSigner))

	// assemble and combine gentx to get genesis file, configure peering between sentries, then start the chain
	Genesis(t, ctx, network, otherValidatorNodes, []*TestNode{}, []*TestValidator{ourValidator})

	// get slice of all nodes so we can wait for them all
	var allNodes TestNodes
	allNodes = append(allNodes, otherValidatorNodes...)
	allNodes = append(allNodes, ourValidator.Sentries...)

	// Wait for all nodes to get to given block height
	allNodes.WaitForHeight(5)

	t.Logf("{%s} -> Checking that slashing has not occurred...", ourValidator.Name())
	require.NoError(t, ourValidator.EnsureNotSlashed())
}

// Test2Of3SignerUniqueSentry will spin up a chain with three single-node validators and one horcrux validator
// the horcrux validator will have three signer nodes with a threshold of two, and one sentry node
// checks that no slashing occurs
func Test2Of3SignerUniqueSentry(t *testing.T) {
	t.Parallel()
	const totalValidators = 4
	const totalSentries = 2
	const totalSigners = 3
	const threshold = 2
	const sentriesPerSigner = 1
	chain := getSimdChain()

	ctx, home, pool, network := SetupTestRun(t)

	// set the test cleanup function
	t.Cleanup(Cleanup(pool, t.Name(), home))

	// build the horcrux image
	require.NoError(t, BuildTestSignerImage(pool))

	// setup a horcrux validator for us
	ourValidator := NewHorcruxValidator(t, pool, home, chainID, 0, totalSentries, totalSigners, threshold, chain)

	// remaining validators are single-node non-horcrux
	otherValidatorNodes := GetValidators(1, totalValidators-1, 1, home, chainID, chain, pool, t)

	// start our validator's horcrux cluster
	require.NoError(t, ourValidator.StartHorcruxCluster(ctx, network, sentriesPerSigner))

	// assemble and combine gentx to get genesis file, configure peering between sentries, then start the chain
	Genesis(t, ctx, network, otherValidatorNodes, []*TestNode{}, []*TestValidator{ourValidator})

	// get slice of all nodes so we can wait for them all
	var allNodes TestNodes
	allNodes = append(allNodes, otherValidatorNodes...)
	allNodes = append(allNodes, ourValidator.Sentries...)

	// Wait for all nodes to get to given block height
	allNodes.WaitForHeight(5)

	t.Logf("{%s} -> Checking that slashing has not occurred...", ourValidator.Name())
	require.NoError(t, ourValidator.EnsureNotSlashed())
}

// TestSingleSignerTwoSentries will spin up a chain with four validators & one sentry node, stop one validator & the
// sentry node, configure those two nodes to be relays for the remote signer, spin up a single remote signer, restart
// the validator/sentry node and check that no slashing occurs
func TestSingleSignerTwoSentries(t *testing.T) {
	t.Parallel()
	const totalValidators = 4
	const totalSentries = 2
	const totalSigners = 1
	chain := getSimdChain()

	ctx, home, pool, network := SetupTestRun(t)

	// set the test cleanup function
	t.Cleanup(Cleanup(pool, t.Name(), home))

	var validators TestNodes
	var sentries TestNodes
	for i := 0; i < totalValidators-1; i++ {
		if i == 0 {
			// first validator will be our validator, add sentry node(s)
			nodes := MakeTestNodes(i, totalSentries, home, chainID, chain, pool, t)
			validators = append(validators, nodes[0])
			sentries = nodes[1:]
		} else {
			validators = append(validators, MakeTestNodes(i, 1, home, chainID, chain, pool, t)...)
		}
	}

	signers := MakeTestSigners(0, totalSigners, home, pool, t)
	ourValidator := validators[0]
	allNodes := validators
	allNodes = append(allNodes, sentries...)

	// build the horcrux image
	var eg errgroup.Group
	eg.Go(func() error {
		return BuildTestSignerImage(pool)
	})

	// assemble and combine gentx to get genesis file, configure peering between sentries, then start the chain
	Genesis(t, ctx, network, validators, sentries, []*TestValidator{})

	// Wait for all nodes to get to given block heigh
	allNodes.WaitForHeight(5)

	// wait for build to finish
	require.NoError(t, eg.Wait())

	// start remote signer
	StartSingleSignerContainers(t, signers, ourValidator, append(sentries, ourValidator), network)

	// Stop the validator node and sentry node before upgrading to horcrux
	t.Logf("{%s} -> Stopping Node...", ourValidator.Name())
	require.NoError(t, ourValidator.StopContainer())
	require.NoError(t, pool.Client.RemoveContainer(docker.RemoveContainerOptions{ID: ourValidator.Container.ID}))

	t.Logf("{%s} -> Stopping Node...", sentries[0].Name())
	require.NoError(t, sentries[0].StopContainer())
	require.NoError(t, pool.Client.RemoveContainer(docker.RemoveContainerOptions{ID: sentries[0].Container.ID}))

	time.Sleep(5 * time.Second) // wait for all containers to stop

	// wait for all signers to be reachable on port 2222
	require.NoError(t, signers.GetHosts().WaitForAllToStart(t, 10))

	// modify node config to listen for private validator connections
	ourValidator.SetPrivValdidatorListen(allNodes.PeerString())
	sentries[0].SetPrivValdidatorListen(allNodes.PeerString())

	// restart node and ensure that signer cluster is connected by
	// checking if the node continues to miss blocks or is slashed
	t.Logf("{%s} -> Restarting Node...", ourValidator.Name())
	t.Logf("{%s} -> Restarting Node...", sentries[0].Name())

	require.NoError(t, ourValidator.CreateNodeContainer(network.ID))
	require.NoError(t, sentries[0].CreateNodeContainer(network.ID))

	require.NoError(t, ourValidator.StartContainer(ctx))
	require.NoError(t, sentries[0].StartContainer(ctx))

	// wait for our validator and all sentries to be reachable
	hosts := ourValidator.GetHosts()
	hosts = append(hosts, sentries[0].GetHosts()...)
	require.NoError(t, hosts.WaitForAllToStart(t, 10))

	t.Logf("{%s} -> Checking that slashing has not occurred...", ourValidator.Name())
	ourPrivVal, err := ourValidator.GetPrivVal()
	require.NoError(t, err)

	require.NoError(t, ourValidator.EnsureNotSlashed(ourPrivVal.PubKey.Address()))
}

// TestUpgradeValidatorToHorcrux will spin up a chain with four validators, stop one validator, configure that validator
// to be a relay for the remote signer cluster, spin up a 2/3 threshold signer cluster, restart the validator and check
// that no slashing occurs
func TestUpgradeValidatorToHorcrux(t *testing.T) {
	t.Parallel()
	// NOTE: have this test skipped because we are debugging the docker build in CI
	// t.Skip()
	const totalValidators = 4
	const totalSigners = 3
	const threshold = 2
	const sentriesPerSigner = 1
	chain := getSimdChain()

	ctx, home, pool, network := SetupTestRun(t)

	// set the test cleanup function
	t.Cleanup(Cleanup(pool, t.Name(), home))

	// start building the horcrux image
	var eg errgroup.Group
	eg.Go(func() error {
		return BuildTestSignerImage(pool)
	})

	var validators TestNodes
	for i := 0; i < totalValidators-1; i++ {
		validators = append(validators, MakeTestNodes(i, 1, home, chainID, chain, pool, t)...)
	}

	ourValidatorNode := validators[0]

	// assemble and combine gentx to get genesis file, configure peering between sentries, then start the chain
	Genesis(t, ctx, network, validators, []*TestNode{}, []*TestValidator{})

	// Wait for all validators to get to given block height
	validators.WaitForHeight(5)

	// wait for build to finish
	require.NoError(t, eg.Wait())

	ourValidatorPrivValKey, err := ourValidatorNode.GetPrivVal()
	require.NoError(t, err)

	// create horcrux validator with same consensus key
	ourValidatorUpgradedToHorcrux := NewHorcruxValidatorWithPrivValKey(t, pool, home, chainID,
		0, 0, totalSigners, threshold, getSimdChain(), ourValidatorPrivValKey)

	// Stop our validator node before upgrading to horcrux
	t.Logf("{%s} -> Stopping Node...", ourValidatorNode.Name())
	require.NoError(t, ourValidatorNode.StopContainer())
	require.NoError(t, pool.Client.RemoveContainer(docker.RemoveContainerOptions{ID: ourValidatorNode.Container.ID}))

	time.Sleep(5 * time.Second) // wait for all containers to stop

	// bring in single signer node as a sentry for horcrux
	ourValidatorUpgradedToHorcrux.Sentries = []*TestNode{ourValidatorNode}

	// modify node config to listen for private validator connections
	ourValidatorNode.SetPrivValdidatorListen(validators.PeerString())

	// TODO re-initialize priv_validator_key.json for ourValidatorNode to be certain it is no longer signing

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
	const totalValidators = 4
	const totalSigners = 3
	const totalSentries = 2
	const threshold = 2
	const sentriesPerSigner = 3
	chain := getSimdChain()

	ctx, home, pool, network := SetupTestRun(t)

	// set the test cleanup function
	t.Cleanup(Cleanup(pool, t.Name(), home))

	// build the horcrux image
	require.NoError(t, BuildTestSignerImage(pool))

	// setup a horcrux validator for us
	ourValidator := NewHorcruxValidator(t, pool, home, chainID, 0, totalSentries, totalSigners, threshold, chain)

	// remaining validators are single-node non-horcrux
	otherValidatorNodes := GetValidators(1, totalValidators-1, 1, home, chainID, chain, pool, t)

	// start our validator's horcrux cluster
	require.NoError(t, ourValidator.StartHorcruxCluster(ctx, network, sentriesPerSigner))

	// assemble and combine gentx to get genesis file, configure peering between sentries, then start the chain
	Genesis(t, ctx, network, otherValidatorNodes, []*TestNode{}, []*TestValidator{ourValidator})

	// get slice of all nodes so we can wait for them all
	var allNodes TestNodes
	allNodes = append(allNodes, otherValidatorNodes...)
	allNodes = append(allNodes, ourValidator.Sentries...)

	// Wait for all nodes to get to given block height
	allNodes.WaitForHeight(5)

	t.Logf("{%s} -> Checking that slashing has not occurred...", ourValidator.Name())
	require.NoError(t, ourValidator.EnsureNotSlashed())

	// Test taking down each node in the signer cluster for a period of time
	for _, signer := range ourValidator.Signers {
		t.Logf("{%s} -> Stopping signer...", signer.Name())
		require.NoError(t, signer.StopContainer())
		require.NoError(t, pool.Client.RemoveContainer(docker.RemoveContainerOptions{ID: signer.Container.ID}))

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
	const totalValidators = 4
	const totalSigners = 5
	const totalSentries = 4
	const threshold = 3
	const sentriesPerSigner = 5
	chain := getSimdChain()

	ctx, home, pool, network := SetupTestRun(t)

	// set the test cleanup function
	t.Cleanup(Cleanup(pool, t.Name(), home))

	// build the horcrux image
	require.NoError(t, BuildTestSignerImage(pool))

	// setup a horcrux validator for us
	ourValidator := NewHorcruxValidator(t, pool, home, chainID, 0, totalSentries, totalSigners, threshold, chain)

	// remaining validators are single-node non-horcrux
	otherValidatorNodes := GetValidators(1, totalValidators-1, 1, home, chainID, chain, pool, t)

	// start our validator's horcrux cluster
	require.NoError(t, ourValidator.StartHorcruxCluster(ctx, network, sentriesPerSigner))

	// assemble and combine gentx to get genesis file, configure peering between sentries, then start the chain
	Genesis(t, ctx, network, otherValidatorNodes, []*TestNode{}, []*TestValidator{ourValidator})

	// get slice of all nodes so we can wait for them all
	var allNodes TestNodes
	allNodes = append(allNodes, otherValidatorNodes...)
	allNodes = append(allNodes, ourValidator.Sentries...)

	// Wait for all nodes to get to given block height
	allNodes.WaitForHeight(5)

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
			require.NoError(t, signer1.StopContainer())
			require.NoError(t, pool.Client.RemoveContainer(docker.RemoveContainerOptions{ID: signer1.Container.ID}))
			t.Logf("{%s} -> Stopping signer...", signer2.Name())
			require.NoError(t, signer2.StopContainer())
			require.NoError(t, pool.Client.RemoveContainer(docker.RemoveContainerOptions{ID: signer2.Container.ID}))
			t.Logf("{%s} -> Waiting until cluster recovers from taking down signer {%s}", ourValidator.Name(), signer1.Name())
		} else {
			t.Logf("{%s} -> Stopping signer...", signer2.Name())
			require.NoError(t, signer2.StopContainer())
			require.NoError(t, pool.Client.RemoveContainer(docker.RemoveContainerOptions{ID: signer2.Container.ID}))
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
	const totalValidators = 4
	const signersPerValidator = 3
	const sentriesPerValidator = 2
	const threshold = 2
	const sentriesPerSigner = sentriesPerValidator
	chain := getSimdChain()

	ctx, home, pool, network := SetupTestRun(t)

	// build horcrux docker image
	require.NoError(t, BuildTestSignerImage(pool))

	// set the test cleanup function
	t.Cleanup(Cleanup(pool, t.Name(), home))

	var validators []*TestValidator
	var startValidatorsErrGroup errgroup.Group

	var allNodes TestNodes

	// start horcrux cluster for each validator
	for i := 0; i < totalValidators; i++ {
		validator := NewHorcruxValidator(t, pool, home, chainID, i,
			sentriesPerValidator, signersPerValidator, threshold, chain)
		validators = append(validators, validator)
		allNodes = append(allNodes, validator.Sentries...)
		startValidatorsErrGroup.Go(func() error {
			return validator.StartHorcruxCluster(ctx, network, sentriesPerSigner)
		})
	}

	require.NoError(t, startValidatorsErrGroup.Wait())

	// assemble and combine gentx to get genesis file, configure peering between sentries, then start the chain
	Genesis(t, ctx, network, []*TestNode{}, []*TestNode{}, validators)

	allNodes.WaitForHeight(5)

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
