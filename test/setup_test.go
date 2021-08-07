package test

import (
	"context"
	"fmt"
	"io/ioutil"
	"net"
	"os"
	"path"
	"strings"
	"testing"

	"github.com/ory/dockertest"
	"github.com/ory/dockertest/docker"
	"github.com/strangelove-ventures/horcrux/signer"
	"github.com/stretchr/testify/require"
	"golang.org/x/sync/errgroup"
)

var (
	chainid = "horcrux"
)

func SetupTestRun(t *testing.T, numNodes int) (context.Context, string, *dockertest.Pool, *docker.Network, TestNodes) {

	home, err := ioutil.TempDir("", "")
	require.NoError(t, err)

	pool, err := dockertest.NewPool("")
	require.NoError(t, err)

	network, err := CreateTestNetwork(pool, fmt.Sprintf("horcrux-%s", RandLowerCaseLetterString(8)), t)
	require.NoError(t, err)

	return context.Background(), home, pool, network, MakeTestNodes(numNodes, home, chainid, simdChain, pool, t)
}

// StartNodeContainers is passed a chain id and arrays of validators and full nodes to configure
func StartNodeContainers(t *testing.T, ctx context.Context, net *docker.Network, validators, fullnodes []*TestNode) {
	var eg errgroup.Group

	// sign gentx for each validator
	for _, v := range validators {
		v := v
		eg.Go(func() error { return v.InitValidatorFiles(ctx) })
	}

	// just initialize folder for any full nodes
	for _, n := range fullnodes {
		n := n
		eg.Go(func() error { return n.InitFullNodeFiles(ctx) })
	}

	// wait for this to finish
	require.NoError(t, eg.Wait())

	// for the validators we need to collect the gentxs and the accounts
	// to the first node's genesis file
	validator0 := validators[0]
	for i := 1; i < len(validators); i++ {
		i := i
		eg.Go(func() error {
			validatorN := validators[i]
			n0key, err := validatorN.GetKey(valKey)
			if err != nil {
				return err
			}

			if err := validator0.AddGenesisAccount(ctx, n0key.GetAddress().String()); err != nil {
				return err
			}
			nNid, err := validatorN.NodeID()
			if err != nil {
				return err
			}
			oldPath := path.Join(validatorN.Dir(), "config", "gentx", fmt.Sprintf("gentx-%s.json", nNid))
			newPath := path.Join(validator0.Dir(), "config", "gentx", fmt.Sprintf("gentx-%s.json", nNid))
			return os.Rename(oldPath, newPath)
		})
	}
	require.NoError(t, eg.Wait())
	require.NoError(t, validator0.CollectGentxs(ctx))

	genbz, err := ioutil.ReadFile(validator0.GenesisFilePath())
	require.NoError(t, err)

	nodes := append(validators, fullnodes...)

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

func StartSignerContainers(t *testing.T, testSigners TestSigners, node *TestNode, threshold, total int, network *docker.Network) {
	eg := new(errgroup.Group)
	ctx := context.Background()

	// init config files/directory for each signer node
	for _, s := range testSigners {
		s := s
		eg.Go(func() error { return s.InitSignerConfig(ctx, "tcp://node-0:1234", testSigners, s.Index, threshold) })
	}
	require.NoError(t, eg.Wait())

	// generate key shares from node private key
	tn.t.Logf("{%s} -> Creating Private Key Shares...", tn.Name())
	shares, err := node.CreateKeyShares(int64(threshold), int64(total))
	require.NoError(t, err)
	for i, signer := range testSigners {
		signer := signer
		signer.Key = shares[i]
	}

	// write key share to file in each signer nodes config directory
	for _, s := range testSigners {
		// signer := signer
		s.t.Logf("{%s} -> Writing Key Share To File... ", s.Name())
		privateFilename := fmt.Sprintf("%sshare.json", s.Dir())
		require.NoError(t, signer.WriteCosignerShareFile(s.Key, privateFilename))
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
	// require.NoError(t, os.RemoveAll(dir))

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

func CreateTestNetwork(pool *dockertest.Pool, name string, t *testing.T) (*docker.Network, error) {
	return pool.Client.CreateNetwork(docker.CreateNetworkOptions{
		Name:           name,
		CheckDuplicate: true,
		Internal:       false,
		Context:        context.Background(),
		Labels:         map[string]string{"horcrux-test": t.Name()},
	})
}
