package signer

import (
	"context"
	"os"
	"testing"
	"time"

	cometlog "github.com/cometbft/cometbft/libs/log"
	"github.com/stretchr/testify/require"
)

type mockPruner struct {
	cnc    *CosignerNonceCache
	count  int
	pruned int
}

func (mp *mockPruner) PruneNonces() int {
	mp.count++
	pruned := mp.cnc.PruneNonces()
	mp.pruned += pruned
	return pruned
}

func TestNonceCacheDemand(t *testing.T) {
	lcs, _ := getTestLocalCosigners(t, 2, 3)
	cosigners := make([]Cosigner, len(lcs))
	for i, lc := range lcs {
		cosigners[i] = lc
	}

	mp := &mockPruner{}

	nonceCache := NewCosignerNonceCache(
		cometlog.NewTMLogger(cometlog.NewSyncWriter(os.Stdout)),
		cosigners,
		&MockLeader{id: 1, leader: &ThresholdValidator{myCosigner: lcs[0]}},
		500*time.Millisecond,
		100*time.Millisecond,
		2,
		mp,
	)

	mp.cnc = nonceCache

	ctx, cancel := context.WithCancel(context.Background())

	nonceCache.LoadN(ctx, 500)

	go nonceCache.Start(ctx)

	for i := 0; i < 3000; i++ {
		_, err := nonceCache.GetNonces([]Cosigner{cosigners[0], cosigners[1]})
		require.NoError(t, err)
		time.Sleep(10 * time.Millisecond)
		require.Greater(t, nonceCache.cache.Size(), 0)
	}

	size := nonceCache.cache.Size()

	require.Greater(t, size, 0)

	cancel()

	require.LessOrEqual(t, size, nonceCache.target())

	require.Greater(t, mp.count, 0)
	require.Equal(t, 0, mp.pruned)
}
