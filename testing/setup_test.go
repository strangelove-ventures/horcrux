package testing

import (
	"crypto/sha256"
	"fmt"
	"io/ioutil"
	"os"
	"path"
	"testing"
	"time"

	"github.com/ory/dockertest/v3"
	"github.com/stretchr/testify/require"
	"golang.org/x/sync/errgroup"
)

func TestTestnet(t *testing.T) {
	home, err := ioutil.TempDir("", "")
	require.NoError(t, err)

	// uses a sensible default on windows (tcp/http) and linux/osx (socket)
	pool, err := dockertest.NewPool("")
	if err != nil {
		require.NoError(t, fmt.Errorf("could not connect to docker at %s: %w", pool.Client.Endpoint(), err))
	}

	nodes := MakeTestNodes(4, home, "horcrux", simdChain, pool)

	// setup testnet files
	require.NoError(t, setupMultiValTestnetFiles(t, pool, nodes))

	require.NoError(t, err)

	for _, n := range nodes {
		gen, err := ioutil.ReadFile(path.Join(n.Dir(), "config", "genesis.json"))
		require.NoError(t, err)
		t.Log(fmt.Sprintf("node-%d genesis hash: %x", n.Index, sha256.Sum256(gen)))
	}

	// t.Log("genesis", string(info))
	// t.Log("node-id", nodes[0].NodeID())
	t.Log("nodes started?")
	time.Sleep(60 * time.Second)

	for _, n := range nodes {
		require.Equal(t, 1, len(n.KeysList()))
	}

}

// setupMultiValTestnetFiles is passed a chain id and number chains to spin up
func setupMultiValTestnetFiles(t *testing.T, pool *dockertest.Pool, nodes []*TestNode) error {
	eg := new(errgroup.Group)
	// sign gentx for each node
	t.Log("starting seeding node files")
	for _, n := range nodes {
		n := n
		eg.Go(n.InitNodeFilesAndGentx)
	}

	if err := eg.Wait(); err != nil {
		return err
	}

	t.Log("begin genesis generation")
	// add genesis accounts for other nodes in the first node's genesis and move their gentxs to first node
	node0 := nodes[0]
	for i := 1; i < len(nodes); i++ {
		nodeN := nodes[i]
		if err := node0.AddGenesisAccount(nodeN.GetKey(valKey).GetAddress().String()); err != nil {
			return err
		}
		if err := os.Rename(nodeN.GentxPath(), path.Join(node0.Dir(), "config", "gentx", fmt.Sprintf("gentx-%s.json", nodeN.NodeID()))); err != nil {
			return err
		}
	}

	t.Log("collect gentxs and copy genesis file to other nodes")
	// collect gentxs on the first node
	if err := node0.CollectGentxs(); err != nil {
		return err
	}

	t.Log("waiting for genesis")
	// wait for genesis to be ready
	if err := node0.GenesisReady(); err != nil {
		return err
	}

	// copy genesis file bytes into memory
	genbz, err := ioutil.ReadFile(node0.GenesisFilePath())
	if err != nil {
		return err
	}

	// overwrite all the other genesis files
	for i := 1; i < len(nodes); i++ {
		if err := ioutil.WriteFile(nodes[i].GenesisFilePath(), genbz, 0644); err != nil {
			return err
		}
	}

	t.Log("modify config for each node")
	// modify config for the nodes
	for _, n := range nodes {
		peers := TestNodes(nodes).Peers(n)
		if err := n.ModifyConfig(peers); err != nil {
			return err
		}
	}

	t.Log("starting nodes")
	// start nodes
	for _, n := range nodes {
		n := n
		eg.Go(n.StartNode)
	}

	return eg.Wait()
}
