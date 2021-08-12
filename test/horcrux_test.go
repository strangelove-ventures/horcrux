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
	require.NoError(t, BuildTestSignerContainer(pool))
}

// TestSingleSignerTwoSentries will spin up a chain with four validators & one full node, stop one validator & full node,
// configure those two nodes to be relays for the remote signer, spin up a single remote signer, restart the validator
// and check that no slashing occurs
func TestSingleSignerTwoSentries(t *testing.T) {
	const numValidators = 4
	const numFullNodes = 1
	const totalSigners = 1

	ctx, home, pool, network, validators := SetupTestRun(t, numValidators+numFullNodes)
	testSigners := MakeTestSigners(totalSigners, home, pool, t)
	fullNodes := validators[numValidators:]
	validators = validators[:numValidators]
	allNodes := append(validators, fullNodes...)

	// start building the cosigner container first
	var eg errgroup.Group
	eg.Go(func() error {
		return BuildTestSignerContainer(pool)
	})

	// start validators and full node
	StartNodeContainers(t, ctx, network, validators, fullNodes)

	// Wait for all nodes to get to block 15
	allNodes.WaitForHeight(15)

	// wait for build to finish
	require.NoError(t, eg.Wait())

	// Stop the validator node and full node before spinning up the signer node
	t.Logf("{%s} -> Stopping Node...", validators[0].Name())
	require.NoError(t, validators[0].StopContainer())

	t.Logf("{%s} -> Stopping Node...", fullNodes[0].Name())
	require.NoError(t, fullNodes[0].StopContainer())

	// set the test cleanup function
	t.Cleanup(Cleanup(pool, t.Name(), home))

	// start signer processes
	StartSingleSignerContainers(t, testSigners, validators[0], append(fullNodes, validators[0]), network)

	// TODO: how to block till signer containers start?
	// once we have prometheus server we can poll that
	// time.Sleep(10 * time.Second)

	// modify node config to listen for private validator connections
	validators[0].SetPrivValdidatorListen(allNodes.PeerString())
	fullNodes[0].SetPrivValdidatorListen(allNodes.PeerString())

	// restart node and ensure that signer cluster is connected by
	// checking if the node continues to miss blocks or is slashed
	t.Logf("{%s} -> Restarting Node...", validators[0].Name())
	t.Logf("{%s} -> Restarting Node...", fullNodes[0].Name())

	// TODO: can we just restart the container
	require.NoError(t, validators[0].CreateNodeContainer(network.ID, true))
	require.NoError(t, fullNodes[0].CreateNodeContainer(network.ID, true))

	require.NoError(t, validators[0].StartContainer(ctx))
	require.NoError(t, fullNodes[0].StartContainer(ctx))

	time.Sleep(10 * time.Second)

	t.Logf("{%s} -> Checking that slashing has not occurred...", validators[0].Name())
	validators[0].EnsureNotSlashed()
}

// TestUpgradeValidatorToHorcrux will spin up a chain with four validators, stop one validator, configure that validator
// to be a relay for the remote signers, spin up a 2/3 threshold signer cluster, restart the validator and check that no slashing occurs
func TestUpgradeValidatorToHorcrux(t *testing.T) {
	// NOTE: have this test skipped because we are debugging the docker build in CI
	// t.Skip()
	const numNodes = 4
	const totalSigners = 3
	const threshold = 2

	ctx, home, pool, network, nodes := SetupTestRun(t, numNodes)
	testSigners := MakeTestSigners(totalSigners, home, pool, t)

	// start building the cosigner container first
	var eg errgroup.Group
	eg.Go(func() error {
		return BuildTestSignerContainer(pool)
	})

	// start validators
	StartNodeContainers(t, ctx, network, nodes, []*TestNode{})

	// Wait for all nodes to get to block 15
	nodes.WaitForHeight(15)

	// wait for build to finish
	require.NoError(t, eg.Wait())

	// Stop one validator node before spinning up the mpc nodes
	t.Logf("{%s} -> Stopping Node...", nodes[0].Name())
	require.NoError(t, nodes[0].StopContainer())

	// set the test cleanup function
	t.Cleanup(Cleanup(pool, t.Name(), home))

	// start signer processes
	StartCosignerContainers(t, testSigners, nodes[0], TestNodes{nodes[0]}, threshold, totalSigners, network)

	// TODO: how to block till signer containers start?
	// once we have prometheus server we can poll that
	// time.Sleep(10 * time.Second)

	// modify node config to listen for private validator connections
	nodes[0].SetPrivValdidatorListen(nodes.PeerString())

	// restart node and ensure that signer cluster is connected by
	// checking if the node continues to miss blocks or is slashed
	t.Logf("{%s} -> Restarting Node...", nodes[0].Name())

	// TODO: can we just restart the container
	require.NoError(t, nodes[0].CreateNodeContainer(network.ID, true))

	require.NoError(t, nodes[0].StartContainer(ctx))

	time.Sleep(10 * time.Second)

	t.Logf("{%s} -> Checking that slashing has not occurred...", nodes[0].Name())
	nodes[0].EnsureNotSlashed()
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
