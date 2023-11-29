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

func TestClearNonces(t *testing.T) {
	lcs, _ := getTestLocalCosigners(t, 2, 3)
	cosigners := make([]Cosigner, len(lcs))
	for i, lc := range lcs {
		cosigners[i] = lc
	}

	cnc := CosignerNonceCache{
		threshold: 2,
	}

	for i := 0; i < 10; i++ {
		// When deleting nonce for cosigner 1 ([0]),
		// these nonce will drop below threshold and be deleted.
		cnc.cache.Add(&CachedNonce{
			UUID:       uuid.New(),
			Expiration: time.Now().Add(1 * time.Second),
			Nonces: []CosignerNoncesRel{
				{Cosigner: cosigners[0]},
				{Cosigner: cosigners[1]},
			},
		})
		// When deleting nonce for cosigner 1 ([0]), these nonces will still be above threshold,
		// so they will remain without cosigner 1.
		cnc.cache.Add(&CachedNonce{
			UUID:       uuid.New(),
			Expiration: time.Now().Add(1 * time.Second),
			Nonces: []CosignerNoncesRel{
				{Cosigner: cosigners[0]},
				{Cosigner: cosigners[1]},
				{Cosigner: cosigners[2]},
			},
		})
	}

	require.Equal(t, 20, cnc.cache.Size())

	cnc.ClearNonces(cosigners[0])

	require.Equal(t, 10, cnc.cache.Size())

	for _, n := range cnc.cache.cache {
		require.Len(t, n.Nonces, 2)
	}
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
		500*time.Millisecond,
		2,
		mp,
	)

	mp.cnc = nonceCache

	ctx, cancel := context.WithCancel(context.Background())

	const loadN = 500

	nonceCache.LoadN(ctx, loadN)

	go nonceCache.Start(ctx)

	time.Sleep(1 * time.Second)

	count, pruned := mp.Result()

	// we should have pruned at least three times after
	// waiting for a second with a reconcile interval of 250ms
	require.GreaterOrEqual(t, count, 3)

	// we should have pruned at least the number of nonces we loaded and knew would expire
	require.GreaterOrEqual(t, pruned, loadN)

	cancel()

	// the cache should have at most the trim padding since no nonces are being consumed.
	require.LessOrEqual(t, nonceCache.cache.Size(), targetTrim)
}
