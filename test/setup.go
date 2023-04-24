package test

import (
	"bytes"
	"context"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/cosmos/cosmos-sdk/types"
	"github.com/ory/dockertest"
	"github.com/ory/dockertest/docker"
	"github.com/strangelove-ventures/horcrux/signer"
	"github.com/stretchr/testify/require"
	"golang.org/x/sync/errgroup"
)

type Logger interface {
	Name() string
	Log(...interface{})
	Logf(string, ...interface{})
}

func SetupTestRun(t *testing.T) (context.Context, string, *dockertest.Pool, string) {
	home := t.TempDir()

	pool, err := dockertest.NewPool("")
	require.NoError(t, err)

	// set the test cleanup function
	t.Cleanup(Cleanup(pool, t, home))

	// run cleanup to cleanup stale resources from any killed tests
	Cleanup(pool, t, home)()

	network, err := CreateTestNetwork(pool, fmt.Sprintf("horcrux-%s", RandLowerCaseLetterString(8)), t)
	require.NoError(t, err)

	// build the horcrux image
	require.NoError(t, BuildSignerImage(pool))

	return context.Background(), home, pool, network.ID
}

// assemble gentx, build genesis file, configure peering, and start chain
func Genesis(
	ctx context.Context,
	tl Logger,
	chain *ChainType,
	nonHorcruxValidators,
	fullnodes []*Node,
	horcruxValidators []*Validator,
) error {
	var eg errgroup.Group

	// sign gentx for each validator
	for _, v := range nonHorcruxValidators {
		if v.ChainID != chain.ChainID {
			continue
		}
		v := v
		// passing empty pubkey to use the one from the validator after it is initialized
		eg.Go(func() error { return v.InitValidatorFiles(ctx, "") })
	}

	for _, v := range horcruxValidators {
		v := v

		bech32Prefix := ""
		if chain.PubKeyAsBech32 {
			bech32Prefix = chain.Bech32Prefix
		}

		pubKey, err := signer.PubKey(bech32Prefix, v.PubKey)
		if err != nil {
			return err
		}

		i := 0
		var firstSentry *Node

		for ; i < len(v.Sentries); i++ {
			if v.Sentries[i].ChainID == chain.ChainID {
				firstSentry = v.Sentries[i]
				break
			}
		}

		if firstSentry == nil {
			return fmt.Errorf("no sentry found for chain id: %s", chain.ChainID)
		}

		// using the first sentry for each horcrux validator as the keyring for the account key (not consensus key)
		// to sign gentx
		eg.Go(func() error {
			return firstSentry.InitValidatorFiles(ctx, pubKey)
		})
		for i++; i < len(v.Sentries); i++ {
			s := v.Sentries[i]
			if s.ChainID != chain.ChainID {
				continue
			}
			eg.Go(func() error { return s.InitFullNodeFiles(ctx) })
		}
	}

	// just initialize folder for any full nodes
	for _, n := range fullnodes {
		n := n
		if n.ChainID != chain.ChainID {
			continue
		}
		eg.Go(func() error { return n.InitFullNodeFiles(ctx) })
	}

	// wait for this to finish
	if err := eg.Wait(); err != nil {
		return err
	}

	var validators Nodes
	var nodes Nodes

	for _, v := range nonHorcruxValidators {
		if v.ChainID != chain.ChainID {
			continue
		}
		validators = append(validators, v)
		nodes = append(nodes, v)
	}

	for _, horcruxValidator := range horcruxValidators {
		if len(horcruxValidator.Sentries) > 0 {
			var firstSentry *Node
			for _, n := range horcruxValidator.Sentries {
				if n.ChainID == chain.ChainID {
					firstSentry = n
					break
				}
			}
			if firstSentry == nil {
				return fmt.Errorf("no sentry found for chain id: %s", chain.ChainID)
			}
			// for test purposes, account key (not consensus key) will come from first sentry
			validators = append(validators, firstSentry)
		}

		for _, n := range horcruxValidator.Sentries {
			if n.ChainID == chain.ChainID {
				nodes = append(nodes, n)
			}
		}
	}

	for _, n := range fullnodes {
		if n.ChainID == chain.ChainID {
			nodes = append(nodes, n)
		}
	}

	// for the validators we need to collect the gentxs and the accounts
	// to a single node's genesis file. We will use the first validator
	validatorNodeToUseForGenTx := validators[0]

	for i := 1; i < len(validators); i++ {
		validatorN := validators[i]
		n0key, err := validatorN.GetKey(valKey)
		if err != nil {
			return err
		}

		bech32Address, err := types.Bech32ifyAddressBytes(chain.Bech32Prefix, n0key.GetAddress())
		if err != nil {
			return err
		}
		if err := validatorNodeToUseForGenTx.AddGenesisAccount(ctx, bech32Address); err != nil {
			return err
		}
		nNid, err := validatorN.NodeID()
		if err != nil {
			return err
		}
		oldPath := filepath.Join(validatorN.Dir(), "config", "gentx", fmt.Sprintf("gentx-%s.json", nNid))
		newPath := filepath.Join(validatorNodeToUseForGenTx.Dir(), "config", "gentx", fmt.Sprintf("gentx-%s.json", nNid))
		if err := os.Rename(oldPath, newPath); err != nil {
			return err
		}
	}
	if err := eg.Wait(); err != nil {
		return err
	}
	if err := validatorNodeToUseForGenTx.CollectGentxs(ctx); err != nil {
		return err
	}

	genbz, err := os.ReadFile(validatorNodeToUseForGenTx.GenesisFilePath())
	if err != nil {
		return err
	}

	for i := 1; i < len(nodes); i++ {
		if err := os.WriteFile(nodes[i].GenesisFilePath(), genbz, 0644); err != nil { //nolint
			return err
		}
	}

	if err := nodes.LogGenesisHashes(); err != nil {
		return err
	}

	peers := nodes.PeerString()

	// start horcrux sentries. privval listener enabled
	for _, v := range horcruxValidators {
		for _, sentry := range v.Sentries {
			if sentry.ChainID != chain.ChainID {
				continue
			}
			s := sentry
			tl.Logf("{%s} => starting container...", s.Name())
			eg.Go(func() error {
				return s.Start(ctx, func() {
					s.SetValidatorConfigAndPeers(peers, true)
				})
			})
		}
	}

	// start non-horcrux validators. privval listener disabled
	for _, v := range nonHorcruxValidators {
		if v.ChainID != chain.ChainID {
			continue
		}
		v := v
		tl.Logf("{%s} => starting container...", v.Name())
		eg.Go(func() error {
			return v.Start(ctx, func() {
				v.SetValidatorConfigAndPeers(peers, false)
			})
		})
	}

	// start full nodes. privval listener disabled
	for _, n := range fullnodes {
		if n.ChainID != chain.ChainID {
			continue
		}
		n := n
		tl.Logf("{%s} => starting container...", n.Name())
		eg.Go(func() error {
			return n.Start(ctx, func() {
				n.SetValidatorConfigAndPeers(peers, false)
			})
		})
	}

	return eg.Wait()
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
func Cleanup(pool *dockertest.Pool, t *testing.T, testDir string) func() {
	return func() {
		cont, _ := pool.Client.ListContainers(docker.ListContainersOptions{All: true})
		ctx := context.Background()
		for _, c := range cont {
			for k, v := range c.Labels {
				if k == "horcrux-test" && v == t.Name() {
					_ = pool.Client.StopContainer(c.ID, 10)
					_, _ = pool.Client.WaitContainerWithContext(c.ID, ctx)
					if t.Failed() {
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
				if k == "horcrux-test" && v == t.Name() {
					_ = pool.Client.RemoveNetwork(n.ID)
				}
			}
		}
		_ = os.RemoveAll(testDir)
	}
}
