package testing

import (
	"context"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"path"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"github.com/testcontainers/testcontainers-go"
	"golang.org/x/sync/errgroup"
)

var (
	chainid = "horcux"
	netid   = "horcrux"
)

// disable logging from testcontainers
func init() {
	log.Default().SetOutput(ioutil.Discard)
}

func TestUpgradeValidatorToHorcrux(t *testing.T) {
	testsDone := make(chan struct{})
	contDone := make(chan struct{})
	home, err := ioutil.TempDir("", "")
	require.NoError(t, err)

	ctx := context.Background()
	provider, err := testcontainers.NewDockerProvider()
	require.NoError(t, err)

	net, err := provider.CreateNetwork(ctx, testcontainers.NetworkRequest{Name: netid, Internal: false})
	require.NoError(t, err)

	nodes := MakeTestNodes(4, home, chainid, simdChain, provider)

	cont := startValidatorContainers(t, provider, net, nodes)
	require.NoError(t, err)
	nodes.LogGenesisHashes(t)

	// set the test cleanup function
	go cleanUpTest(t, testsDone, contDone, cont, net, home)
	t.Cleanup(func() {
		testsDone <- struct{}{}
		<-contDone
	})

	for i, n := range nodes {
		str, err := cont[i].PortEndpoint(ctx, "26657", "http")
		require.NoError(t, err)
		fmt.Printf("%s available at %s\n", n.Name(), str)
		require.NoError(t, n.NewClient(str))
	}

	time.Sleep(10 * time.Second)

	t.Log("nodes started waiting 60 seconds before teardown")
	time.Sleep(60 * time.Second)
	// TODO: init 3 signer directories
	// TODO: stop one node
	// TODO: generate keys shares from node private key
	// TODO: copy key shares to signer node directories
	// TODO: modify node config to listen for priv_validator connections
}

// startValidatorContainers is passed a chain id and number chains to spin up
func startValidatorContainers(t *testing.T, pool *testcontainers.DockerProvider, net testcontainers.Network, nodes []*TestNode) []testcontainers.Container {
	eg := new(errgroup.Group)
	ctx := context.Background()
	// sign gentx for each node
	t.Log("starting seeding node files")
	for _, n := range nodes {
		n := n
		eg.Go(func() error { return n.InitNodeFilesAndGentx(ctx) })
	}
	require.NoError(t, eg.Wait())

	t.Log("begin genesis generation")
	node0 := nodes[0]
	for i := 1; i < len(nodes); i++ {
		nodeN := nodes[i]
		n0key, err := nodeN.GetKey(valKey)
		require.NoError(t, err)

		// add genesis account for node to the first node's genesis file
		_, err = node0.AddGenesisAccount(ctx, n0key.GetAddress().String())
		require.NoError(t, err)

		nNid, err := nodeN.NodeID()
		require.NoError(t, err)

		// Move gentx file to first node's directory
		oldPath := path.Join(nodeN.Dir(), "config", "gentx", fmt.Sprintf("gentx-%s.json", nNid))
		newPath := path.Join(node0.Dir(), "config", "gentx", fmt.Sprintf("gentx-%s.json", nNid))
		require.NoError(t, os.Rename(oldPath, newPath))
	}

	t.Log("collect gentxs")
	_, err := node0.CollectGentxs(ctx)
	require.NoError(t, err)

	// copy genesis file bytes into memory
	t.Log("read final genesis file")
	genbz, err := ioutil.ReadFile(node0.GenesisFilePath())
	require.NoError(t, err)

	t.Log("overwrite genesis files")
	for i := 1; i < len(nodes); i++ {
		require.NoError(t, ioutil.WriteFile(nodes[i].GenesisFilePath(), genbz, 0644))
	}

	t.Log("creating node containers")
	cont := make([]testcontainers.Container, len(nodes))
	for i, n := range nodes {
		n, i := n, i
		eg.Go(func() error {
			res, err := n.CreateNodeContainer(ctx)
			if err != nil {
				return err
			}
			cont[i] = res
			return nil
		})
	}
	t.Log("waiting for containers to create")
	require.NoError(t, eg.Wait())

	t.Log("getting peer string")
	peers, err := peerString(ctx, nodes)
	require.NoError(t, err)
	t.Log("peer string", peers)
	t.Log("setting configs")
	for _, n := range nodes {
		n.SetValidatorConfigAndPeers(peers)
	}
	t.Log("start node containers")
	for i, c := range cont {
		c := c
		t.Logf("starting node-%d", i)
		eg.Go(func() error { return c.Start(ctx) })
	}
	require.NoError(t, eg.Wait())
	t.Log("nodes started")

	return cont
}

// peerString returns the string for connecting the nodes passed in
func peerString(ctx context.Context, nodes []*TestNode) (out string, err error) {
	bldr := new(strings.Builder)
	for _, n := range nodes {
		id, err := n.NodeID()
		if err != nil {
			return bldr.String(), err
		}
		bldr.WriteString(fmt.Sprintf("%s@%s:26656,", id, n.Name()))
	}
	return strings.TrimSuffix(bldr.String(), ","), nil
}

// cleanUpTest is trigged by t.Cleanup and cleans up all resorces from the test
func cleanUpTest(t *testing.T, testsDone <-chan struct{}, contDone chan<- struct{}, cont []testcontainers.Container, net testcontainers.Network, dir string) {
	// block here until tests are complete
	<-testsDone

	// clean up the tmp dir
	require.NoError(t, os.RemoveAll(dir))

	// remove all the docker containers
	for _, r := range cont {
		require.NoError(t, r.Terminate(context.Background()))
	}

	// remove the docker network
	require.NoError(t, net.Remove(context.Background()))

	// Notify the t.Cleanup that cleanup is done
	contDone <- struct{}{}
}
