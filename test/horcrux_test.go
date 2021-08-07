package test

import (
	"testing"
	"time"

	"github.com/ory/dockertest"
	"github.com/stretchr/testify/require"
	"golang.org/x/sync/errgroup"
)

func TestBuildSignerContainer(t *testing.T) {
	// NOTE: this test isn't skipped because we are debbuging it in CIs
	t.Skip()
	pool, err := dockertest.NewPool("")
	require.NoError(t, err)
	require.NoError(t, BuildTestSignerContainer(pool, t))
}

func TestUpgradeValidatorToHorcrux(t *testing.T) {
	// NOTE: have this test skipped because we are debugging the docker build in CI
	// t.Skip()

	numNodes := 4
	totalSigners := 3
	threshold := 2

	ctx, home, pool, network, nodes, testsDone, contDone := SetupTestRun(t, numNodes)
	testSigners := MakeTestSigners(totalSigners, home, pool, t)

	// start building the cosigner container first
	var eg errgroup.Group
	eg.Go(func() error {
		return BuildTestSignerContainer(pool, t)
	})

	// start validators
	StartNodeContainers(t, ctx, network, nodes, []*TestNode{})

	// Wait for all nodes to get to block 15
	TestNodes(nodes).WaitForHeight(15)

	// wait for build to finish
	require.NoError(t, eg.Wait())

	// Stop one node before spinning up the mpc nodes
	t.Logf("{%s} -> Stopping Node...", nodes[0].Name())
	require.NoError(t, nodes[0].StopContainer())

	// set the test cleanup function
	go cleanUpTest(t, testsDone, contDone, pool, nodes, testSigners, network, home)
	t.Cleanup(func() {
		testsDone <- struct{}{}
		<-contDone
	})

	// start signer processes
	StartSignerContainers(t, testSigners, nodes[0], threshold, totalSigners, network)

	// modify node config to listen for private validator connections
	peers, err := peerString(nodes, t)
	require.NoError(t, err)
	nodes[0].SetPrivValdidatorListen(peers)

	// restart node and ensure that signer cluster is connected by
	// checking if the node continues to miss blocks or is slashed
	t.Logf("{%s} -> Restarting Node...", nodes[0].Name())

	// TODO: can we just restart the container
	err = nodes[0].CreateNodeContainer(network.ID)
	require.NoError(t, err)

	err = nodes[0].StartContainer(ctx)
	require.NoError(t, err)

	time.Sleep(10 * time.Second)

	nodes[0].EnsureNotSlashed()
}
