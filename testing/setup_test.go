package testing

import (
	"context"
	"crypto/sha256"
	"fmt"
	"io/ioutil"
	"os"
	"path"
	"testing"
	"time"

	"github.com/ory/dockertest/v3"
	"github.com/stretchr/testify/require"
	"github.com/testcontainers/testcontainers-go"
	"golang.org/x/sync/errgroup"
)

var (
	chainid = "horcux"
	netid   = "horcrux"
)

func TestTestnet(t *testing.T) {
	home, err := ioutil.TempDir("", "")
	require.NoError(t, err)

	ctx := context.Background()
	// uses a sensible default on windows (tcp/http) and linux/osx (socket)
	provider, err := testcontainers.NewDockerProvider()
	require.NoError(t, err)

	// TODO: do we need a network?
	// net, err := provider.CreateNetwork(ctx, testcontainers.NetworkRequest{})
	// require.NoError(t, err)

	nodes := MakeTestNodes(4, home, chainid, simdChain, provider)

	// setup testnet files
	res, err := setupMultiValTestnetFiles(t, provider, nodes)
	require.NoError(t, err)

	require.NoError(t, err)

	for _, n := range nodes {
		gen, err := ioutil.ReadFile(path.Join(n.Dir(), "config", "genesis.json"))
		require.NoError(t, err)
		t.Log(fmt.Sprintf("node-%d genesis hash: %x", n.Index, sha256.Sum256(gen)))
	}

	t.Log("nodes started?")
	time.Sleep(60 * time.Second)

	// Purge resources
	for _, r := range res {
		require.NoError(t, r.Terminate(ctx))
	}

	// TODO: if we need network be sure to remove it
	// require.NoError(t, net.Remove(ctx))
}

// setupMultiValTestnetFiles is passed a chain id and number chains to spin up
func setupMultiValTestnetFiles(t *testing.T, pool *testcontainers.DockerProvider, nodes []*TestNode) ([]testcontainers.Container, error) {
	eg, ctx := errgroup.WithContext(context.Background())
	// sign gentx for each node
	t.Log("starting seeding node files")
	for _, n := range nodes {
		// n := n
		// eg.Go(func() error { return n.InitNodeFilesAndGentx(ctx) })
		if err := n.InitNodeFilesAndGentx(ctx); err != nil {
			return nil, err
		}
	}
	// if err := eg.Wait(); err != nil {
	// 	return nil, err
	// }

	t.Log("begin genesis generation")
	// add genesis accounts for other nodes in the first node's genesis and move their gentxs to first node
	node0 := nodes[0]
	for i := 1; i < len(nodes); i++ {
		nodeN := nodes[i]
		n0key, err := nodeN.GetKey(valKey)
		if err != nil {
			return nil, err
		}
		if _, err := node0.AddGenesisAccount(ctx, n0key.GetAddress().String()); err != nil {
			return nil, err
		}
		nNpth, err := nodeN.GentxPath()
		if err != nil {
			return nil, err
		}
		nNid, err := nodeN.NodeID()
		if err != nil {
			return nil, err
		}
		if err := os.Rename(nNpth, path.Join(node0.Dir(), "config", "gentx", fmt.Sprintf("gentx-%s.json", nNid))); err != nil {
			return nil, err
		}
	}

	t.Log("collect gentxs and copy genesis file to other nodes")
	// collect gentxs on the first node
	if _, err := node0.CollectGentxs(ctx); err != nil {
		return nil, err
	}

	// copy genesis file bytes into memory
	genbz, err := ioutil.ReadFile(node0.GenesisFilePath())
	if err != nil {
		return nil, err
	}

	// overwrite all the other genesis files
	for i := 1; i < len(nodes); i++ {
		if err := ioutil.WriteFile(nodes[i].GenesisFilePath(), genbz, 0644); err != nil {
			return nil, err
		}
	}

	t.Log("starting nodes")
	// start nodes
	resources := make([]testcontainers.Container, len(nodes))
	for i, n := range nodes {
		n, i := n, i
		eg.Go(func() error {
			res, err := n.CreateNodeContainer(ctx)
			if err != nil {
				return err
			}
			resources[i] = res
			return nil
		})
	}

	t.Log("modify config for each node")
	// modify config for the nodes
	for _, n := range nodes {
		peers := TestNodes(nodes).Peers(n)
		// TODO: modify?
		if err := n.SetValidatorConfigAndPeers(peers); err != nil {
			return nil, err
		}
	}

	return resources, eg.Wait()
}

// cleanUpTest is called as a goroutine to wait until the tests have completed and
// cleans up the docker items created
func cleanUpTest(t *testing.T, testsDone <-chan struct{}, contDone chan<- struct{},
	resources []*dockertest.Resource, network *dockertest.Network, pool *dockertest.Pool, dir string) {
	// block here until tests are complete
	<-testsDone

	// clean up the tmp dir
	if err := os.RemoveAll(dir); err != nil {
		require.NoError(t, fmt.Errorf("{cleanUpTest} failed to rm dir(%w), %s ", err, dir))
	}

	// remove all the docker containers
	for _, r := range resources {
		if err := pool.Purge(r); err != nil {
			require.NoError(t, fmt.Errorf("could not purge container %s: %w", r.Container.Name, err))
		}
	}

	require.NoError(t, pool.RemoveNetwork(network))

	// Notify the other side that we have deleted the docker containers
	contDone <- struct{}{}
}
