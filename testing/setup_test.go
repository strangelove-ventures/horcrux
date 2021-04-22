package testing

import (
	"fmt"
	"io/ioutil"
	"testing"

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
	require.NoError(t, setupMultiValTestnetFiles(pool, nodes))

	for _, n := range nodes {
		require.Equal(t, 1, len(n.KeysList()))
	}
}

// setupMultiValTestnetFiles is passed a chain id and number chains to spin up
func setupMultiValTestnetFiles(pool *dockertest.Pool, nodes []*TestNode) error {
	val := "validator"
	eg := new(errgroup.Group)
	for _, n := range nodes {
		n := n
		eg.Go(func() error {
			if err := n.InitHomeFolder(); err != nil {
				return err
			}
			if err := n.CreateKey(val); err != nil {
				return err
			}
			if err := n.AddGenesisAccount(val); err != nil {
				return err
			}
			if err := n.Gentx(val); err != nil {
				return err
			}
			return nil
		})
	}
	err := eg.Wait()
	return err
}
