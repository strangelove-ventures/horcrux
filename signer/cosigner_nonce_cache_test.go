package signer

import (
	"context"
	"os"
	"sync"
	"testing"
	"time"

	cometlog "github.com/cometbft/cometbft/libs/log"
	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
)

func TestNonceCache(_ *testing.T) {
	nc := NonceCache{}
	for i := 0; i < 10; i++ {
		nc.Add(&CachedNonce{UUID: uuid.New(), Expiration: time.Now().Add(1 * time.Second)})
	}

	nc.Delete(nc.Size() - 1)
	nc.Delete(0)
}

type mockPruner struct {
	cnc    *CosignerNonceCache
	count  int
	pruned int
	mu     sync.Mutex
}

func (mp *mockPruner) PruneNonces() int {
	pruned := mp.cnc.PruneNonces()
	mp.mu.Lock()
	defer mp.mu.Unlock()
	mp.count++
	mp.pruned += pruned
	return pruned
}

func (mp *mockPruner) Result() (int, int) {
	mp.mu.Lock()
	defer mp.mu.Unlock()
	return mp.count, mp.pruned
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
		defaultNonceExpiration,
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

func TestNonceCacheExpiration(t *testing.T) {
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
		250*time.Millisecond,
		10*time.Millisecond,
		1*time.Second,
		2,
		mp,
	)

	mp.cnc = nonceCache

	ctx, cancel := context.WithCancel(context.Background())

	nonceCache.LoadN(ctx, 500)

	go nonceCache.Start(ctx)

	time.Sleep(520 * time.Millisecond)

	nonceCache.LoadN(ctx, 500)

	time.Sleep(520 * time.Millisecond)

	size := nonceCache.cache.Size()

	require.Equal(t, size, 500+targetTrim)

	count, pruned := mp.Result()

	require.Equal(t, count, 6)
	require.Equal(t, 500, pruned)

	time.Sleep(520 * time.Millisecond)

	count, pruned = mp.Result()

	require.Equal(t, count, 8)
	require.Equal(t, 1010, pruned)

	cancel()

	size = nonceCache.cache.Size()

	require.Equal(t, size, targetTrim)
}
