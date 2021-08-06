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
	slashingtypes "github.com/cosmos/cosmos-sdk/x/slashing/types"
	"github.com/ory/dockertest"
	"github.com/ory/dockertest/docker"
	"github.com/stretchr/testify/require"
	tmcfg "github.com/tendermint/tendermint/config"
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

	/*
		On Linux based systems Docker daemon runs as root and any containers run are also run under root.
		This has introduced the problem of not being able to access resources created by Docker containers from inside
		of a user account on the host machine without sudo (i.e. can't read the files from Go)

		As of now, when creating a docker container the config is being passed in a uid:gid string to tell the container
		to explicitly be ran from said user/group. Below code dynamically grabs the uid but it makes the assumption
		that the gid will be equal to the uid on Linux based systems or that the user will belong to the group 'admin'
		on MacOS
	*/

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

	// Build horcrux image from current Dockerfile
	go func() {
		t.Logf("Building Docker Image %s:%s", imageName, imageVer)
		options := docker.BuildImageOptions{
			Name:           fmt.Sprintf("%s:%s", imageName, imageVer),
			Dockerfile:     dockerFile,
			OutputStream:   ioutil.Discard,
			RmTmpContainer: true,
			ContextDir:     fmt.Sprintf("%s%s", os.Getenv("GOPATH"), ctxDir),
		}
		err = pool.Client.BuildImage(options)
		require.NoError(t, err)
	}()

	nodes := MakeTestNodes(4, home, chainid, simdChain, pool, t)

	startValidatorContainers(t, network, nodes)

	t.Log("Waiting For Nodes To Reach Block Height 15...")
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
				t.Logf("{%s} => reached block 15\n", n.Name())
				return nil
			})
		})
	}
	require.NoError(t, eg.Wait())

	// Create test signers
	total := 3
	threshold := 2
	testSigners := MakeTestSigners(total, home, pool, t)

	// Stop one node before spinning up the mpc nodes
	t.Logf("{%s} -> Stopping Node...", nodes[0].Name())
	err = nodes[0].StopContainer()
	require.NoError(t, err)

	// set the test cleanup function
	go cleanUpTest(t, testsDone, contDone, pool, nodes, testSigners, network, home)
	t.Cleanup(func() {
		testsDone <- struct{}{}
		<-contDone
	})

	startSignerContainers(t, testSigners, nodes[0], threshold, total, network)

	// modify node config to listen for private validator connections
	peers, err := peerString(nodes, t)
	require.NoError(t, err)

	cfg := tmcfg.DefaultConfig()
	cfg.BaseConfig.PrivValidatorListenAddr = "tcp://0.0.0.0:1234"
	stdconfigchanges(cfg, peers) // Reapply the changes made to the config file in SetValidatorConfigAndPeers()
	tmcfg.WriteConfigFile(nodes[0].TMConfigPath(), cfg)

	// restart node and check that slashing doesn't happen and cluster continues to make blocks
	t.Logf("{%s} -> Restarting Node...", nodes[0].Name())
	err = nodes[0].CreateNodeContainer(network.ID)
	require.NoError(t, err)

	err = nodes[0].StartContainer(ctx)
	require.NoError(t, err)

	time.Sleep(10 * time.Second)

	consPub, err := nodes[0].GetConsPub()
	require.NoError(t, err)

	missed := int64(0)
	for i := 0; i < 10; i++ {
		time.Sleep(1 * time.Second)
		slashInfo, err := slashingtypes.NewQueryClient(nodes[0].CliContext()).SigningInfo(context.Background(), &slashingtypes.QuerySigningInfoRequest{
			ConsAddress: consPub,
		})
		require.NoError(t, err)

		if i == 0 {
			missed = slashInfo.ValSigningInfo.MissedBlocksCounter
			continue
		}
		require.Equal(t, missed, slashInfo.ValSigningInfo.MissedBlocksCounter)
		require.False(t, slashInfo.ValSigningInfo.Tombstoned)
	}
}

// startValidatorContainers is passed a chain id and number chains to spin up
func startValidatorContainers(t *testing.T, net *docker.Network, nodes []*TestNode) {
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
			return n.CreateNodeContainer(net.ID)
		})
	}
	require.NoError(t, eg.Wait())

	peers, err := peerString(nodes, t)
	require.NoError(t, err)

	for _, n := range nodes {
		n := n
		t.Logf("{%s} => starting container...", n.Name())
		eg.Go(func() error {
			n.SetValidatorConfigAndPeers(peers)
			return n.StartContainer(ctx)
		})
	}
	require.NoError(t, eg.Wait())
}

func startSignerContainers(t *testing.T, testSigners TestSigners, node *TestNode, threshold, total int, network *docker.Network) {
	eg := new(errgroup.Group)
	ctx := context.Background()

	// init config files/directory for each signer node
	for _, s := range testSigners {
		s := s
		eg.Go(func() error { return s.InitSignerConfig(ctx, "tcp://node-0:1234", testSigners, s.Index, threshold) })
	}
	require.NoError(t, eg.Wait())

	// generate key shares from node private key
	shares, err := node.CreateKeyShares(int64(threshold), int64(total))
	require.NoError(t, err)
	for i, signer := range testSigners {
		signer := signer
		signer.Key = shares[i]
	}

	// write key share to file in each signer nodes config directory
	for _, signer := range testSigners {
		signer := signer
		_ = signer.WriteKeyToFile()
	}

	// create containers & start signer nodes
	for _, signer := range testSigners {
		signer := signer
		eg.Go(func() error {
			return signer.CreateSignerContainer(network.ID)
		})
	}
	require.NoError(t, eg.Wait())

	for _, s := range testSigners {
		s := s
		t.Logf("{%s} => starting container...", s.Name())
		eg.Go(func() error {
			return s.StartContainer()
		})
	}
	require.NoError(t, eg.Wait())
}

// peerString returns the string for connecting the nodes passed in
func peerString(nodes []*TestNode, t *testing.T) (out string, err error) {
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
func cleanUpTest(t *testing.T, testsDone <-chan struct{}, contDone chan<- struct{}, pool *dockertest.Pool, nodes []*TestNode, signers TestSigners, net *docker.Network, dir string) {
	// block here until tests are complete
	<-testsDone

	// remove all the docker containers
	var eg errgroup.Group
	for _, r := range nodes {
		r := r
		eg.Go(func() error {
			if err := r.StopContainer(); err != nil {
				t.Log("error stopping container", err)
			}
			return nil
		})
	}
	require.NoError(t, eg.Wait())

	for _, s := range signers {
		s := s
		eg.Go(func() error {
			if err := s.StopContainer(); err != nil {
				t.Log("error stopping container", err)
			}
			return nil
		})
	}
	require.NoError(t, eg.Wait())

	// remove the docker network
	require.NoError(t, pool.Client.RemoveNetwork(net.ID))

	// clean up the tmp dir
	require.NoError(t, os.RemoveAll(dir))

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
