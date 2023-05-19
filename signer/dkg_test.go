package signer

import (
	"context"
	"crypto/rand"
	"testing"

	"github.com/libp2p/go-libp2p/core/crypto"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/stretchr/testify/require"
	tsed25519 "gitlab.com/unit410/threshold-ed25519/pkg"
	"golang.org/x/sync/errgroup"
)

func TestNetworkDKG(t *testing.T) {
	ctx := context.Background()

	cosigners := []CosignerConfig{
		{
			ShardID: 1,
			P2PAddr: "tcp://127.0.0.1:8040",
		},
		{
			ShardID: 2,
			P2PAddr: "tcp://127.0.0.1:8041",
		},
		{
			ShardID: 3,
			P2PAddr: "tcp://127.0.0.1:8042",
		},
	}

	cosignerPrivKeys := make([]crypto.PrivKey, len(cosigners))

	for i := range cosigners {
		privKey, _, err := crypto.GenerateEd25519Key(rand.Reader)
		require.NoError(t, err)

		p2pID, err := peer.IDFromPrivateKey(privKey)
		require.NoError(t, err)

		cosigners[i].DKGID = p2pID.String()

		cosignerPrivKeys[i] = privKey
	}

	const threshold = 2

	var eg errgroup.Group

	shards := make([]*CosignerEd25519Key, len(cosigners))

	for i, c := range cosigners {
		id := c.ShardID
		i := i
		eg.Go(func() (err error) {
			shards[i], err = NetworkDKG(ctx, cosigners, id, cosignerPrivKeys[i], threshold)
			return err
		})
	}

	require.NoError(t, eg.Wait())

	pubKey := shards[0].PubKey

	privShards := make([]tsed25519.Scalar, len(cosigners))

	for i, shard := range shards {
		privShards[i] = shard.PrivateShard
	}

	testThresholdValidatorWithShards(t, threshold, uint8(len(cosigners)), pubKey, privShards)
}
