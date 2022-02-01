package test

import (
	"os"
	"testing"
	"time"

	"github.com/ory/dockertest"
	"github.com/ory/dockertest/docker"
	"github.com/stretchr/testify/require"
	"golang.org/x/sync/errgroup"
)

func TestBuildSignerContainer(t *testing.T) {
	// NOTE: this test isn't skipped because we are debbuging it in CIs
	t.Skip()
	pool, err := dockertest.NewPool("")
	require.NoError(t, err)
	require.NoError(t, BuildTestSignerImage(pool))
}

// Test3Of7SignerTwoSentries will spin up a chain with four validators and 5 sentry nodes, stop one validator and all
// the sentry nodes, configure that validator and the sentry nodes to be a relay for the remote signers, spin up a 3/7
// threshold signer cluster, restart the validator/sentry nodes and check that no slashing occurs
func Test3Of7SignerTwoSentries(t *testing.T) {
	t.Parallel()
	const totalValidators = 4
	const totalSentries = 4
	const totalSigners = 7
	const threshold = 3
	const sentriesPerSigner = 2

	ctx, home, pool, network, validators := SetupTestRun(t, totalValidators+totalSentries)
	signers := MakeTestSigners(totalSigners, home, pool, t)
	sentries := validators[totalValidators:]
	validators = validators[:totalValidators]
	ourValidator := validators[0]
	allNodes := validators
	allNodes = append(allNodes, sentries...)

	// start building the cosigner container first
	var eg errgroup.Group
	eg.Go(func() error {
		return BuildTestSignerImage(pool)
	})

	// start validators and sentry nodes
	StartNodeContainers(t, ctx, network, validators, sentries)

	// Wait for all nodes to get to given block height
	allNodes.WaitForHeight(5)

	// wait for build to finish
	require.NoError(t, eg.Wait())

	// start signer cluster
	StartCosignerContainers(t, signers, ourValidator, append(sentries, ourValidator), threshold,
		totalSigners, sentriesPerSigner, network)

	// Stop the validator node and sentry nodes before upgrading to horcrux
	t.Logf("{%s} -> Stopping Node...", ourValidator.Name())
	require.NoError(t, ourValidator.StopContainer())

	for _, fn := range sentries {
		fn := fn
		t.Logf("{%s} -> Stopping Node...", fn.Name())
		eg.Go(func() error {
			return fn.StopContainer()
		})
	}
	require.NoError(t, eg.Wait())

	time.Sleep(5 * time.Second) // wait for all containers to stop

	// set the test cleanup function
	t.Cleanup(Cleanup(pool, t.Name(), home))

	// wait until signer containers are reachable on port 2222
	signers.GetHosts().WaitForAllToStart(t, 10)

	// modify node config to listen for private validator connections
	peerString := allNodes.PeerString()
	ourValidator.SetPrivValdidatorListen(peerString)

	for _, fn := range sentries {
		fn.SetPrivValdidatorListen(peerString)
	}

	// restart node and ensure that signer cluster is connected by
	// checking if the node continues to miss blocks or is slashed
	t.Logf("{%s} -> Restarting Node...", ourValidator.Name())
	require.NoError(t, ourValidator.CreateNodeContainer(network.ID, true))

	for _, fn := range sentries {
		t.Logf("{%s} -> Restarting Node...", fn.Name())
		fn := fn
		eg.Go(func() error {
			return fn.CreateNodeContainer(network.ID, true)
		})
	}
	require.NoError(t, eg.Wait())

	require.NoError(t, ourValidator.StartContainer(ctx))
	for _, fn := range sentries {
		fn := fn
		eg.Go(func() error {
			return fn.StartContainer(ctx)
		})
	}
	require.NoError(t, eg.Wait())

	// wait for our validator and all sentries to be reachable
	hosts := ourValidator.GetHosts()
	hosts = append(hosts, sentries.GetHosts()...)
	hosts.WaitForAllToStart(t, 10)

	t.Logf("{%s} -> Checking that slashing has not occurred...", ourValidator.Name())
	ourValidator.EnsureNotSlashed()
}

// Test2Of3SignerTwoSentries will spin up a chain with four validators and five sentry nodes, stop one validator and all
// the sentry nodes, configure that validator and the sentry nodes to be a relay for the remote signers, spin up a 2/3
// threshold signer cluster, restart the validator/sentry nodes and check that no slashing occurs
func Test2Of3SignerTwoSentries(t *testing.T) {
	t.Parallel()
	const totalValidators = 4
	const totalSentries = 2
	const totalSigners = 3
	const threshold = 2
	const sentriesPerSigner = 2

	ctx, home, pool, network, validators := SetupTestRun(t, totalValidators+totalSentries)
	signers := MakeTestSigners(totalSigners, home, pool, t)
	sentries := validators[totalValidators:]
	validators = validators[:totalValidators]
	ourValidator := validators[0]
	allNodes := validators
	allNodes = append(allNodes, sentries...)

	// start building the cosigner container first
	var eg errgroup.Group
	eg.Go(func() error {
		return BuildTestSignerImage(pool)
	})

	// start validators and sentry nodes
	StartNodeContainers(t, ctx, network, validators, sentries)

	// Wait for all nodes to get to given block height
	allNodes.WaitForHeight(5)

	// wait for build to finish
	require.NoError(t, eg.Wait())

	// start signer cluster
	StartCosignerContainers(t, signers, ourValidator, append(sentries, ourValidator),
		threshold, totalSigners, sentriesPerSigner, network)

	// Stop the validator node and sentry nodes before upgrading to horcrux
	t.Logf("{%s} -> Stopping Node...", ourValidator.Name())
	require.NoError(t, ourValidator.StopContainer())

	for _, fn := range sentries {
		t.Logf("{%s} -> Stopping Node...", fn.Name())
		require.NoError(t, fn.StopContainer())
	}

	time.Sleep(5 * time.Second) // wait for all containers to stop

	// set the test cleanup function
	t.Cleanup(Cleanup(pool, t.Name(), home))

	// wait for all signers to be reachable on port 2222
	signers.GetHosts().WaitForAllToStart(t, 10)

	// modify node config to listen for private validator connections
	peerString := allNodes.PeerString()
	ourValidator.SetPrivValdidatorListen(peerString)

	for _, fn := range sentries {
		fn.SetPrivValdidatorListen(peerString)
	}

	// restart node and ensure that signer cluster is connected by
	// checking if the node continues to miss blocks or is slashed
	t.Logf("{%s} -> Restarting Node...", ourValidator.Name())
	require.NoError(t, ourValidator.CreateNodeContainer(network.ID, true))

	for _, fn := range sentries {
		t.Logf("{%s} -> Restarting Node...", fn.Name())
		require.NoError(t, fn.CreateNodeContainer(network.ID, true))
	}

	require.NoError(t, ourValidator.StartContainer(ctx))
	for _, fn := range sentries {
		require.NoError(t, fn.StartContainer(ctx))
	}

	// wait for validator to be reachable
	ourValidator.GetHosts().WaitForAllToStart(t, 10)

	t.Logf("{%s} -> Checking that slashing has not occurred...", ourValidator.Name())
	ourValidator.EnsureNotSlashed()
}

// Test2Of3SignerUniqueSentry will spin up a chain with four validators and two sentry nodes, stop one validator and all
// sentry nodes, configure that validator and the sentry nodes to be a relay for the remote signers, spin up a 2/3
// threshold signer cluster, restart the validator/sentry nodes and check that no slashing occurs
func Test2Of3SignerUniqueSentry(t *testing.T) {
	t.Parallel()
	const totalValidators = 4
	const totalSentries = 2
	const totalSigners = 3
	const threshold = 2
	const sentriesPerSigner = 1

	ctx, home, pool, network, validators := SetupTestRun(t, totalValidators+totalSentries)
	signers := MakeTestSigners(totalSigners, home, pool, t)
	sentries := validators[totalValidators:]
	validators = validators[:totalValidators]
	ourValidator := validators[0]
	allNodes := validators
	allNodes = append(allNodes, sentries...)

	// start building the cosigner container first
	var eg errgroup.Group
	eg.Go(func() error {
		return BuildTestSignerImage(pool)
	})

	// start validators and sentry nodes
	StartNodeContainers(t, ctx, network, validators, sentries)

	// Wait for all nodes to get to given block height
	allNodes.WaitForHeight(5)

	// wait for build to finish
	require.NoError(t, eg.Wait())

	// start signer cluster
	StartCosignerContainers(t, signers, ourValidator, append(sentries, ourValidator), threshold,
		totalSigners, sentriesPerSigner, network)

	// Stop the validator node and sentry nodes before upgrading to horcrux
	t.Logf("{%s} -> Stopping Node...", ourValidator.Name())
	require.NoError(t, ourValidator.StopContainer())

	for _, fn := range sentries {
		t.Logf("{%s} -> Stopping Node...", fn.Name())
		require.NoError(t, fn.StopContainer())
	}

	time.Sleep(5 * time.Second) // wait for all containers to stop

	// set the test cleanup function
	t.Cleanup(Cleanup(pool, t.Name(), home))

	// wait for all signers to be reachable on port 2222
	signers.GetHosts().WaitForAllToStart(t, 10)

	// modify node config to listen for private validator connections
	peerString := allNodes.PeerString()
	ourValidator.SetPrivValdidatorListen(peerString)

	for _, fn := range sentries {
		fn.SetPrivValdidatorListen(peerString)
	}

	// restart node and ensure that signer cluster is connected by
	// checking if the node continues to miss blocks or is slashed
	t.Logf("{%s} -> Restarting Node...", ourValidator.Name())
	require.NoError(t, ourValidator.CreateNodeContainer(network.ID, true))

	for _, fn := range sentries {
		t.Logf("{%s} -> Restarting Node...", fn.Name())
		require.NoError(t, fn.CreateNodeContainer(network.ID, true))
	}

	require.NoError(t, ourValidator.StartContainer(ctx))
	for _, fn := range sentries {
		require.NoError(t, fn.StartContainer(ctx))
	}

	// wait for our validator and all sentries to be reachable
	hosts := ourValidator.GetHosts()
	hosts = append(hosts, sentries.GetHosts()...)
	hosts.WaitForAllToStart(t, 10)

	t.Logf("{%s} -> Checking that slashing has not occurred...", ourValidator.Name())
	time.Sleep(15 * time.Second)
	ourValidator.EnsureNotSlashed()
}

// TestSingleSignerTwoSentries will spin up a chain with four validators & one sentry node, stop one validator & the
// sentry node, configure those two nodes to be relays for the remote signer, spin up a single remote signer, restart
// the validator/sentry node and check that no slashing occurs
func TestSingleSignerTwoSentries(t *testing.T) {
	t.Parallel()
	const totalValidators = 4
	const totalSentries = 1
	const totalSigners = 1

	ctx, home, pool, network, validators := SetupTestRun(t, totalValidators+totalSentries)
	signers := MakeTestSigners(totalSigners, home, pool, t)
	sentries := validators[totalValidators:]
	validators = validators[:totalValidators]
	ourValidator := validators[0]
	allNodes := validators
	allNodes = append(allNodes, sentries...)

	// start building the cosigner container first
	var eg errgroup.Group
	eg.Go(func() error {
		return BuildTestSignerImage(pool)
	})

	// start validators and sentry node
	StartNodeContainers(t, ctx, network, validators, sentries)

	// Wait for all nodes to get to given block heigh
	allNodes.WaitForHeight(5)

	// wait for build to finish
	require.NoError(t, eg.Wait())

	// start remote signer
	StartSingleSignerContainers(t, signers, ourValidator, append(sentries, ourValidator), network)

	// Stop the validator node and sentry node before upgrading to horcrux
	t.Logf("{%s} -> Stopping Node...", ourValidator.Name())
	require.NoError(t, ourValidator.StopContainer())

	t.Logf("{%s} -> Stopping Node...", sentries[0].Name())
	require.NoError(t, sentries[0].StopContainer())

	time.Sleep(5 * time.Second) // wait for all containers to stop

	// set the test cleanup function
	t.Cleanup(Cleanup(pool, t.Name(), home))

	// wait for all signers to be reachable on port 2222
	signers.GetHosts().WaitForAllToStart(t, 10)

	// modify node config to listen for private validator connections
	ourValidator.SetPrivValdidatorListen(allNodes.PeerString())
	sentries[0].SetPrivValdidatorListen(allNodes.PeerString())

	// restart node and ensure that signer cluster is connected by
	// checking if the node continues to miss blocks or is slashed
	t.Logf("{%s} -> Restarting Node...", ourValidator.Name())
	t.Logf("{%s} -> Restarting Node...", sentries[0].Name())

	require.NoError(t, ourValidator.CreateNodeContainer(network.ID, true))
	require.NoError(t, sentries[0].CreateNodeContainer(network.ID, true))

	require.NoError(t, ourValidator.StartContainer(ctx))
	require.NoError(t, sentries[0].StartContainer(ctx))

	// wait for our validator and all sentries to be reachable
	hosts := ourValidator.GetHosts()
	hosts = append(hosts, sentries[0].GetHosts()...)
	hosts.WaitForAllToStart(t, 10)

	t.Logf("{%s} -> Checking that slashing has not occurred...", ourValidator.Name())
	ourValidator.EnsureNotSlashed()
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
	const sentriesPerSigner = 0

	ctx, home, pool, network, validators := SetupTestRun(t, totalValidators)
	signers := MakeTestSigners(totalSigners, home, pool, t)
	ourValidator := validators[0]

	// start building the cosigner container first
	var eg errgroup.Group
	eg.Go(func() error {
		return BuildTestSignerImage(pool)
	})

	// start validators
	StartNodeContainers(t, ctx, network, validators, []*TestNode{})

	// Wait for all validators to get to given block height
	validators.WaitForHeight(5)

	// wait for build to finish
	require.NoError(t, eg.Wait())

	// start signer cluster
	StartCosignerContainers(t, signers, ourValidator, TestNodes{ourValidator},
		threshold, totalSigners, sentriesPerSigner, network)

	// Stop one validator node before upgrading to horcrux
	t.Logf("{%s} -> Stopping Node...", ourValidator.Name())
	require.NoError(t, ourValidator.StopContainer())

	time.Sleep(5 * time.Second) // wait for all containers to stop

	// set the test cleanup function
	t.Cleanup(Cleanup(pool, t.Name(), home))

	// wait for all signers to be reachable on port 2222
	signers.GetHosts().WaitForAllToStart(t, 10)

	// modify node config to listen for private validator connections
	ourValidator.SetPrivValdidatorListen(validators.PeerString())

	// restart node and ensure that signer cluster is connected by
	// checking if the node continues to miss blocks or is slashed
	t.Logf("{%s} -> Restarting Node...", ourValidator.Name())
	require.NoError(t, ourValidator.CreateNodeContainer(network.ID, true))
	require.NoError(t, ourValidator.StartContainer(ctx))

	// wait for validator to be reachable
	ourValidator.GetHosts().WaitForAllToStart(t, 10)

	t.Logf("{%s} -> Checking that slashing has not occurred...", ourValidator.Name())
	ourValidator.EnsureNotSlashed()
}

func TestDownedSigners2of3(t *testing.T) {
	t.Parallel()
	const totalValidators = 4
	const totalSigners = 3
	const threshold = 2
	const sentriesPerSigner = 0

	ctx, home, pool, network, validators := SetupTestRun(t, totalValidators)
	signers := MakeTestSigners(totalSigners, home, pool, t)
	ourValidator := validators[0]

	// start building the cosigner container first
	var eg errgroup.Group
	eg.Go(func() error {
		return BuildTestSignerImage(pool)
	})

	// start validators
	StartNodeContainers(t, ctx, network, validators, []*TestNode{})

	// Wait for all validators to get to given block height
	validators.WaitForHeight(5)

	// wait for build to finish
	require.NoError(t, eg.Wait())

	// start signer cluster
	StartCosignerContainers(t, signers, ourValidator, TestNodes{ourValidator},
		threshold, totalSigners, sentriesPerSigner, network)

	// Stop our validator node before upgrading to horcrux
	t.Logf("{%s} -> Stopping Node...", ourValidator.Name())
	require.NoError(t, ourValidator.StopContainer())

	time.Sleep(5 * time.Second) // wait for all containers to stop

	// set the test cleanup function
	t.Cleanup(Cleanup(pool, t.Name(), home))

	// wait until signer containers are reachable on port 2222
	signers.GetHosts().WaitForAllToStart(t, 10)

	// modify node config to listen for private validator connections
	ourValidator.SetPrivValdidatorListen(validators.PeerString())

	// restart the validator and ensure that signer cluster is connected by
	// checking if the node continues to miss blocks or is slashed
	t.Logf("{%s} -> Restarting Node...", ourValidator.Name())
	require.NoError(t, ourValidator.CreateNodeContainer(network.ID, true))
	require.NoError(t, ourValidator.StartContainer(ctx))

	// wait for validator to be reachable
	ourValidator.GetHosts().WaitForAllToStart(t, 10)

	t.Logf("{%s} -> Checking that slashing has not occurred...", ourValidator.Name())
	ourValidator.EnsureNotSlashed()

	// Test taking down each node in the signer cluster for a period of time
	for _, signer := range signers {
		t.Logf("{%s} -> Stopping signer...", signer.Name())
		require.NoError(t, signer.StopContainer())

		t.Logf("{%s} -> Waiting until cluster recovers from taking down signer {%s}", ourValidator.Name(), signer.Name())
		ourValidator.WaitUntilStopMissingBlocks()

		t.Logf("{%s} -> Checking that no blocks were missed...", ourValidator.Name())
		ourValidator.EnsureNoMissedBlocks()

		t.Logf("{%s} -> Restarting signer...", signer.Name())
		require.NoError(t, signer.CreateCosignerContainer(network.ID))
		require.NoError(t, signer.StartContainer())
		signer.GetHosts().WaitForAllToStart(t, 10) // Wait to ensure signer is back up
		ourValidator.WaitUntilStopMissingBlocks()
		ourValidator.WaitForConsecutiveBlocks(10)
	}
	t.Logf("{%s} -> Checking that slashing has not occurred...", ourValidator.Name())
	ourValidator.EnsureNotSlashed()
}

func TestDownedSigners3of5(t *testing.T) {
	t.Parallel()
	const totalValidators = 4
	const totalSigners = 5
	const threshold = 3
	const sentriesPerSigner = 0

	ctx, home, pool, network, validators := SetupTestRun(t, totalValidators)
	signers := MakeTestSigners(totalSigners, home, pool, t)
	ourValidator := validators[0]

	// start building the cosigner container first
	var eg errgroup.Group
	eg.Go(func() error {
		return BuildTestSignerImage(pool)
	})

	// start validators
	StartNodeContainers(t, ctx, network, validators, []*TestNode{})

	// Wait for all validators to get to given block height
	validators.WaitForHeight(5)

	// wait for build to finish
	require.NoError(t, eg.Wait())

	// start signer cluster
	StartCosignerContainers(t, signers, ourValidator,
		TestNodes{ourValidator}, threshold, totalSigners, sentriesPerSigner, network)

	// Stop our validator node before upgrading to horcrux
	t.Logf("{%s} -> Stopping Node...", ourValidator.Name())
	require.NoError(t, ourValidator.StopContainer())

	time.Sleep(5 * time.Second) // wait for all containers to stop

	// set the test cleanup function
	t.Cleanup(Cleanup(pool, t.Name(), home))

	// wait until signer containers are reachable on port 2222
	signers.GetHosts().WaitForAllToStart(t, 10)

	// modify node config to listen for private validator connections
	ourValidator.SetPrivValdidatorListen(validators.PeerString())

	// restart the validator and ensure that signer cluster is connected by
	// checking if the node continues to miss blocks or is slashed
	t.Logf("{%s} -> Restarting Node...", ourValidator.Name())
	require.NoError(t, ourValidator.CreateNodeContainer(network.ID, true))
	require.NoError(t, ourValidator.StartContainer(ctx))

	// wait for validator to be reachable
	ourValidator.GetHosts().WaitForAllToStart(t, 10)

	t.Logf("{%s} -> Checking that slashing has not occurred...", ourValidator.Name())
	ourValidator.EnsureNotSlashed()

	// Test taking down 2 nodes at a time in the signer cluster for a period of time
	for i := 0; i < len(signers); i++ {
		signer1 := signers[i]
		var signer2 *TestSigner
		if i < len(signers)-1 {
			signer2 = signers[i+1]
		} else {
			signer2 = signers[0]
		}
		if i == 0 {
			t.Logf("{%s} -> Stopping signer...", signer1.Name())
			require.NoError(t, signer1.StopContainer())
			t.Logf("{%s} -> Stopping signer...", signer2.Name())
			require.NoError(t, signer2.StopContainer())
			t.Logf("{%s} -> Waiting until cluster recovers from taking down signer {%s}", ourValidator.Name(), signer1.Name())
		} else {
			t.Logf("{%s} -> Stopping signer...", signer2.Name())
			require.NoError(t, signer2.StopContainer())
		}

		t.Logf("{%s} -> Waiting until cluster recovers from taking down signer {%s}", ourValidator.Name(), signer2.Name())
		ourValidator.WaitUntilStopMissingBlocks()

		t.Logf("{%s} -> Checking that no blocks were missed...", ourValidator.Name())
		ourValidator.EnsureNoMissedBlocks()

		t.Logf("{%s} -> Restarting signer...", signer1.Name())
		require.NoError(t, signer1.CreateCosignerContainer(network.ID))
		require.NoError(t, signer1.StartContainer())
		signer1.GetHosts().WaitForAllToStart(t, 10) // Wait to ensure signer is back up
		ourValidator.WaitUntilStopMissingBlocks()
		ourValidator.WaitForConsecutiveBlocks(10)
	}
	t.Logf("{%s} -> Checking that slashing has not occurred...", ourValidator.Name())
	ourValidator.EnsureNotSlashed()
}

// Cleanup will clean up Docker containers, networks, and the other various config files generated in testing
func Cleanup(pool *dockertest.Pool, testName, testDir string) func() {
	return func() {
		cont, _ := pool.Client.ListContainers(docker.ListContainersOptions{All: true})
		for _, c := range cont {
			for k, v := range c.Labels {
				if k == "horcrux-test" && v == testName {
					_ = pool.Client.StopContainer(c.ID, 10)
				}
			}
		}
		nets, _ := pool.Client.ListNetworks()
		for _, n := range nets {
			for k, v := range n.Labels {
				if k == "horcrux-test" && v == testName {
					_ = pool.Client.RemoveNetwork(n.ID)
				}
			}
		}
		_ = os.RemoveAll(testDir)
	}
}
