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
	chainid = "horcrux"
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
	pool, err := dockertest.NewPool("")
	require.NoError(t, err)

	network, err := pool.Client.CreateNetwork(docker.CreateNetworkOptions{
		Name:           netid,
		Labels:         map[string]string{},
		CheckDuplicate: true,
		Internal:       false,
		Context:        ctx,
	})
	require.NoError(t, err)

	nodes := MakeTestNodes(4, home, chainid, simdChain, pool, t)

	startValidatorContainers(t, pool, network, nodes)

	// set the test cleanup function
	go cleanUpTest(t, testsDone, contDone, pool, nodes, network, home)
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
				t.Log(stat)
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
	options := docker.BuildImageOptions{
		Name:         fmt.Sprintf("%s:%s", imageName, imageVer),
		Dockerfile:   dockerFile,
		OutputStream: os.Stdout,
		ErrorStream:  os.Stderr,
		ContextDir:   ctxDir,
		Context:      ctx,
	}
	err = pool.Client.BuildImage(options)
	require.NoError(t, err)

	// signer-0 -> horcrux config init horcrux tcp://node-0:1234 --cosigner --peers="tcp://signer-1:1234|2,tcp://signer-2|3" --threshold 2
	// singer-1 -> horcrux config init horcrux tcp://node-0:1234 --cosigner --peers="tcp://signer-0:1234|1,tcp://signer-2|3" --threshold 2
	// signer-2 -> horcrux config init horcrux tcp://node-0:1234 --cosigner --peers="tcp://signer-0:1234|1,tcp://signer-1|2" --threshold 2
	// signer-job -> horcrux
	// TODO: init 3 signer directories
	// TODO: stop one node
	// TODO: generate keys shares from node private key
	// TODO: copy key shares to signer node directories
	// TODO: modify node config to listen for priv_validator connections
	// TODO: restart node and check that slashing doesn't happen and cluster continues to make blocks
}

// startValidatorContainers is passed a chain id and number chains to spin up
func startValidatorContainers(t *testing.T, pool *dockertest.Pool, net *docker.Network, nodes []*TestNode) {
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

	for _, n := range nodes {
		n := n
		eg.Go(func() error {
			return n.CreateNodeContainer(ctx, net.ID)
		})
	}
	require.NoError(t, eg.Wait())

	peers, err := peerString(ctx, nodes, t)
	require.NoError(t, err)

	for _, n := range nodes {
		n := n
		t.Logf("[ %s ] => starting container...", n.Name())
		eg.Go(func() error {
			n.SetValidatorConfigAndPeers(peers)
			return n.StartContainer(ctx)
		})
	}
	require.NoError(t, eg.Wait())
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
func cleanUpTest(t *testing.T, testsDone <-chan struct{}, contDone chan<- struct{}, pool *dockertest.Pool, nodes []*TestNode, net *docker.Network, dir string) {
	// block here until tests are complete
	<-testsDone

	// clean up the tmp dir
	require.NoError(t, os.RemoveAll(dir))

	// remove all the docker containers
	var eg errgroup.Group
	for _, r := range nodes {
		r := r
		eg.Go(func() error {
			if err := r.StopContainer(context.Background()); err != nil {
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
