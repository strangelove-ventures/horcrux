package test

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/avast/retry-go"
	slashingtypes "github.com/cosmos/cosmos-sdk/x/slashing/types"
	"github.com/ory/dockertest"
	"github.com/stretchr/testify/require"
	tmcfg "github.com/tendermint/tendermint/config"
	"golang.org/x/sync/errgroup"
)

func TestBuildSignerContainer(t *testing.T) {
	// NOTE: this test isn't skipped because we are debbuging it in CIs
	// t.Skip()
	pool, err := dockertest.NewPool("")
	require.NoError(t, err)
	require.NoError(t, BuildTestSignerContainer(pool, t))
}

func TestUpgradeValidatorToHorcrux(t *testing.T) {
	// NOTE: have this test skipped because we are debugging the docker build in CI
	t.Skip()

	numNodes := 4
	totalSigners := 3
	threshold := 2

	ctx, home, pool, network, nodes, testsDone, contDone := setupTestRun(t, numNodes)
	testSigners := MakeTestSigners(totalSigners, home, pool, t)

	// start building the cosigner container first
	var eg errgroup.Group
	eg.Go(func() error {
		return BuildTestSignerContainer(pool, t)
	})

	// start validators
	startValidatorContainers(t, ctx, network, nodes, []*TestNode{})

	t.Log("Waiting For Nodes To Reach Block Height 15...")

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

	// Stop one node before spinning up the mpc nodes
	t.Logf("{%s} -> Stopping Node...", nodes[0].Name())
	require.NoError(t, nodes[0].StopContainer())

	// set the test cleanup function
	go cleanUpTest(t, testsDone, contDone, pool, nodes, testSigners, network, home)
	t.Cleanup(func() {
		testsDone <- struct{}{}
		<-contDone
	})

	startSignerContainers(t, testSigners, nodes[0], threshold, totalSigners, network)

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
