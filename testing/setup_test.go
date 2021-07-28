package testing

import (
	"context"
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"os"
	"path"
	"strings"
	"testing"
	"time"

	"github.com/avast/retry-go"
	"github.com/ory/dockertest"
	"github.com/ory/dockertest/docker"
	"github.com/stretchr/testify/require"
	"golang.org/x/sync/errgroup"
)

var (
	chainid = "horcux"
	netid   = "horcrux"
)

// disable logging from dockertest
func init() {
	log.Default().SetOutput(ioutil.Discard)
}

func TestUpgradeValidatorToHorcrux(t *testing.T) {
	testsDone := make(chan struct{})
	contDone := make(chan struct{})
	home, err := ioutil.TempDir("", "")
	require.NoError(t, err)

	ctx := context.Background()
	provider, err := dockertest.NewPool("")
	require.NoError(t, err)

	require.NoError(t, err)

	net, err := provider.Client.CreateNetwork(docker.CreateNetworkOptions{
		Name:   netid,
		Labels: map[string]string{},
		// CheckDuplicate: false, todo: maybe enable?
		Internal: false,
		Context:  ctx,
	})
	require.NoError(t, err)

	nodes := MakeTestNodes(4, home, chainid, simdChain, provider, t)

	cont := startValidatorContainers(t, provider, net, nodes)
	require.NoError(t, err)

	// set the test cleanup function
	go cleanUpTest(t, testsDone, contDone, provider, cont, net, home)
	t.Cleanup(func() {
		testsDone <- struct{}{}
		<-contDone
	})

	var eg errgroup.Group
	for _, n := range nodes {
		n := n
		eg.Go(func() error {
			return retry.Do(func() error {
				stat, err := n.Client.Status(ctx)
				if err != nil {
					return err
				}
				if stat.SyncInfo.CatchingUp || stat.SyncInfo.LatestBlockHeight < 15 {
					return fmt.Errorf("node still under block 15: %d", stat.SyncInfo.LatestBlockHeight)
				}
				t.Logf("[%s] => reached block 15\n", n.Name())
				return nil
			})
		})
	}
	require.NoError(t, eg.Wait())
	t.Log("nodes started waiting 60 seconds before teardown")
	time.Sleep(60 * time.Second)

	// Build horcrux image from current go files
	// signer-0 -> horcrux config init horcrux tcp://node-0:1234
	// singer-1 -> horcrux config init horcrux tcp://node-0:1234
	// signer-2 -> horcrux config init horcrux tcp://node-0:1234
	// signer-job -> horcrux
	// TODO: init 3 signer directories
	// TODO: stop one node
	// TODO: generate keys shares from node private key
	// TODO: copy key shares to signer node directories
	// TODO: modify node config to listen for priv_validator connections
	// TODO: restart node and check that slashing doesn't happen and cluster continues to make blocks
}

// startValidatorContainers is passed a chain id and number chains to spin up
func startValidatorContainers(t *testing.T, pool *dockertest.Pool, net *docker.Network, nodes []*TestNode) []*docker.Container {
	eg := new(errgroup.Group)
	ctx := context.Background()

	// sign gentx for each node
	for _, n := range nodes {
		n := n
		eg.Go(func() error { return n.InitNodeFilesAndGentx(ctx) })
	}
	require.NoError(t, eg.Wait())

	node0 := nodes[0]
	for i := 1; i < len(nodes); i++ {
		nodeN := nodes[i]
		n0key, err := nodeN.GetKey(valKey)
		require.NoError(t, err)

		// add genesis account for node to the first node's genesis file
		require.NoError(t, node0.AddGenesisAccount(ctx, n0key.GetAddress().String()))

		nNid, err := nodeN.NodeID()
		require.NoError(t, err)

		// Move gentx file to first node's directory
		oldPath := path.Join(nodeN.Dir(), "config", "gentx", fmt.Sprintf("gentx-%s.json", nNid))
		newPath := path.Join(node0.Dir(), "config", "gentx", fmt.Sprintf("gentx-%s.json", nNid))
		require.NoError(t, os.Rename(oldPath, newPath))
	}

	require.NoError(t, node0.CollectGentxs(ctx))

	genbz, err := ioutil.ReadFile(node0.GenesisFilePath())
	require.NoError(t, err)

	for i := 1; i < len(nodes); i++ {
		require.NoError(t, ioutil.WriteFile(nodes[i].GenesisFilePath(), genbz, 0644))
	}

	TestNodes(nodes).LogGenesisHashes(t)

	cont := make([]*docker.Container, len(nodes))
	for i, n := range nodes {
		n, i := n, i
		eg.Go(func() error {
			res, err := n.CreateNodeContainer(ctx, net.ID)
			if err != nil {
				return err
			}
			cont[i] = res
			return nil
		})
	}
	require.NoError(t, eg.Wait())

	peers, err := peerString(ctx, nodes, t)
	require.NoError(t, err)

	for _, n := range nodes {
		n.SetValidatorConfigAndPeers(peers)
	}

	for i, c := range cont {
		i, c := i, c
		t.Logf("[node-%d] => starting container...", i)
		eg.Go(func() error {
			if err := pool.Client.StartContainer(c.ID, nil); err != nil {
				return err
			}

			c, err := pool.Client.InspectContainer(c.ID)
			if err != nil {
				return err
			}

			port := GetHostPort(c, "26657/tcp")
			t.Logf("[%s] RPC => %s", nodes[i].Name(), port)

			if err := nodes[i].NewClient(fmt.Sprintf("http://%s", port)); err != nil {
				return err
			}

			return pool.Retry(func() error {
				stat, err := nodes[i].Client.Status(context.Background())
				if err != nil {
					return err
				}
				if stat != nil && !stat.SyncInfo.CatchingUp {
					return fmt.Errorf("still catching up")
				}
				return nil
			})
		})
	}
	require.NoError(t, eg.Wait())
	return cont
}

// peerString returns the string for connecting the nodes passed in
func peerString(ctx context.Context, nodes []*TestNode, t *testing.T) (out string, err error) {
	bldr := new(strings.Builder)
	for _, n := range nodes {
		id, err := n.NodeID()
		if err != nil {
			return bldr.String(), err
		}
		ps := fmt.Sprintf("%s@%s:26656,", id, n.Name())
		t.Logf("{%s} peering (%s)", n.Name(), strings.TrimSuffix(ps, ","))
		bldr.WriteString(ps)
	}
	return strings.TrimSuffix(bldr.String(), ","), nil
}

// cleanUpTest is trigged by t.Cleanup and cleans up all resorces from the test
func cleanUpTest(t *testing.T, testsDone <-chan struct{}, contDone chan<- struct{}, pool *dockertest.Pool, cont []*docker.Container, net *docker.Network, dir string) {
	// block here until tests are complete
	<-testsDone

	// clean up the tmp dir
	require.NoError(t, os.RemoveAll(dir))

	// remove all the docker containers
	var eg errgroup.Group
	for _, r := range cont {
		r := r
		eg.Go(func() error {
			if err := pool.Client.StopContainer(r.ID, uint(time.Second*30)); err != nil {
				t.Log("error stopping container", err)
			}
			return nil
		})
	}
	require.NoError(t, eg.Wait())

	// remove the docker network
	require.NoError(t, pool.Client.RemoveNetwork(net.ID))

	// Notify the t.Cleanup that cleanup is done
	contDone <- struct{}{}
}

// GetHostPort returns a resource's published port with an address.
func GetHostPort(cont *docker.Container, portID string) string {
	if cont == nil || cont.NetworkSettings == nil {
		return ""
	}

	m, ok := cont.NetworkSettings.Ports[docker.Port(portID)]
	if !ok || len(m) == 0 {
		return ""
	}

	ip := m[0].HostIP
	if ip == "0.0.0.0" {
		ip = "localhost"
	}
	return net.JoinHostPort(ip, m[0].HostPort)
}
