package test

import (
	"bytes"
	"context"
	"fmt"
	"io/ioutil"
	"net"
	"os"
	"path"
	"strings"
	"testing"

	"github.com/cosmos/cosmos-sdk/types"
	"github.com/ory/dockertest"
	"github.com/ory/dockertest/docker"
	"github.com/stretchr/testify/require"
	"golang.org/x/sync/errgroup"
)

func SetupTestRun(t *testing.T) (context.Context, string, *dockertest.Pool, *docker.Network) {
	home, err := ioutil.TempDir("", "")
	require.NoError(t, err)

	pool, err := dockertest.NewPool("")
	require.NoError(t, err)

	network, err := CreateTestNetwork(pool, fmt.Sprintf("horcrux-%s", RandLowerCaseLetterString(8)), t)
	require.NoError(t, err)

	// set the test cleanup function
	t.Cleanup(Cleanup(pool, t.Name(), home))

	// build the horcrux image
	require.NoError(t, BuildTestSignerImage(pool))

	return context.Background(), home, pool, network
}

// assemble gentx, build genesis file, configure peering, and start chain
func Genesis(
	t *testing.T,
	ctx context.Context,
	net *docker.Network,
	chain *ChainType,
	nonHorcruxValidators,
	fullnodes []*TestNode,
	horcruxValidators []*TestValidator,
) {
	var eg errgroup.Group

	// sign gentx for each validator
	for _, v := range nonHorcruxValidators {
		v := v
		// passing empty pubkey to use the one from the validator after it is initialized
		eg.Go(func() error { return v.InitValidatorFiles(ctx, "") })
	}

	for _, v := range horcruxValidators {
		v := v
		// using the first sentry for each horcrux validator as the keyring for the account key (not consensus key)
		// to sign gentx
		eg.Go(func() error {
			return v.Sentries[0].InitValidatorFiles(ctx, v.PubKey(chain.Bech32Prefix, chain.PubKeyAsBech32))
		})
		sentries := v.Sentries[1:]
		for _, sentry := range sentries {
			s := sentry
			eg.Go(func() error { return s.InitFullNodeFiles(ctx) })
		}
	}

	// just initialize folder for any full nodes
	for _, n := range fullnodes {
		n := n
		eg.Go(func() error { return n.InitFullNodeFiles(ctx) })
	}

	// wait for this to finish
	require.NoError(t, eg.Wait())

	var validators TestNodes
	var nodes TestNodes

	validators = append(validators, nonHorcruxValidators...)
	nodes = append(nodes, nonHorcruxValidators...)

	for _, horcruxValidator := range horcruxValidators {
		if len(horcruxValidator.Sentries) > 0 {
			// for test purposes, account key (not consensus key) will come from first sentry
			validators = append(validators, horcruxValidator.Sentries[0])
		}
		nodes = append(nodes, horcruxValidator.Sentries...)
	}

	nodes = append(nodes, fullnodes...)

	// for the validators we need to collect the gentxs and the accounts
	// to a single node's genesis file. We will use the first validator
	validatorNodeToUseForGenTx := validators[0]

	for i := 1; i < len(validators); i++ {
		validatorN := validators[i]
		n0key, err := validatorN.GetKey(valKey)
		require.NoError(t, err)

		bech32Address, err := types.Bech32ifyAddressBytes(chain.Bech32Prefix, n0key.GetAddress())
		require.NoError(t, err)
		require.NoError(t, validatorNodeToUseForGenTx.AddGenesisAccount(ctx, bech32Address))
		nNid, err := validatorN.NodeID()
		require.NoError(t, err)
		oldPath := path.Join(validatorN.Dir(), "config", "gentx", fmt.Sprintf("gentx-%s.json", nNid))
		newPath := path.Join(validatorNodeToUseForGenTx.Dir(), "config", "gentx", fmt.Sprintf("gentx-%s.json", nNid))
		require.NoError(t, os.Rename(oldPath, newPath))
	}
	require.NoError(t, eg.Wait())
	require.NoError(t, validatorNodeToUseForGenTx.CollectGentxs(ctx))

	genbz, err := ioutil.ReadFile(validatorNodeToUseForGenTx.GenesisFilePath())
	require.NoError(t, err)

	for i := 1; i < len(nodes); i++ {
		require.NoError(t, ioutil.WriteFile(nodes[i].GenesisFilePath(), genbz, 0644)) //nolint
	}

	nodes.LogGenesisHashes()

	for _, n := range nodes {
		n := n
		eg.Go(func() error {
			return n.CreateNodeContainer(net.ID)
		})
	}
	require.NoError(t, eg.Wait())

	peers := nodes.PeerString()

	// start horcrux sentries. privval listener enabled
	for _, v := range horcruxValidators {
		for _, sentry := range v.Sentries {
			s := sentry
			t.Logf("{%s} => starting container...", s.Name())
			eg.Go(func() error {
				s.SetValidatorConfigAndPeers(peers, true)
				return s.StartContainer(ctx)
			})
		}
	}

	// start non-horcrux validators. privval listener disabled
	for _, v := range nonHorcruxValidators {
		v := v
		t.Logf("{%s} => starting container...", v.Name())
		eg.Go(func() error {
			v.SetValidatorConfigAndPeers(peers, false)
			return v.StartContainer(ctx)
		})
	}

	// start full nodes. privval listener disabled
	for _, n := range fullnodes {
		n := n
		t.Logf("{%s} => starting container...", n.Name())
		eg.Go(func() error {
			n.SetValidatorConfigAndPeers(peers, false)
			return n.StartContainer(ctx)
		})
	}

	require.NoError(t, eg.Wait())
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
		Options:        map[string]interface{}{},
		Labels:         map[string]string{"horcrux-test": t.Name()},
		CheckDuplicate: true,
		Internal:       false,
		EnableIPv6:     false,
		Context:        context.Background(),
	})
}

// Cleanup will clean up Docker containers, networks, and the other various config files generated in testing
func Cleanup(pool *dockertest.Pool, testName, testDir string) func() {
	return func() {
		cont, _ := pool.Client.ListContainers(docker.ListContainersOptions{All: true})
		ctx := context.Background()
		for _, c := range cont {
			for k, v := range c.Labels {
				if k == "horcrux-test" && v == testName {
					_ = pool.Client.StopContainer(c.ID, 10)
					_, err := pool.Client.WaitContainerWithContext(c.ID, ctx)
					if err != nil {
						stdout := new(bytes.Buffer)
						stderr := new(bytes.Buffer)
						_ = pool.Client.Logs(docker.LogsOptions{
							Context:      ctx,
							Container:    c.ID,
							OutputStream: stdout,
							ErrorStream:  stderr,
							Stdout:       true,
							Stderr:       true,
							Tail:         "100",
							Follow:       false,
							Timestamps:   false,
						})
						fmt.Printf("{%s}\nstdout:\n%s\nstderr:\n%s\n", strings.Join(c.Names, ","), stdout, stderr)
					}
					_ = pool.Client.RemoveContainer(docker.RemoveContainerOptions{ID: c.ID})
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
