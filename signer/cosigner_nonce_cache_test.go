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

func TestMovingAverage(t *testing.T) {
	ma := newMovingAverage(12 * time.Second)

	ma.add(3*time.Second, 500)
	require.Len(t, ma.items, 1)
	require.Equal(t, float64(500), ma.average())

	ma.add(3*time.Second, 100)
	require.Len(t, ma.items, 2)
	require.Equal(t, float64(300), ma.average())

	ma.add(6*time.Second, 600)
	require.Len(t, ma.items, 3)
	require.Equal(t, float64(450), ma.average())

	// should kick out the first one
	ma.add(3*time.Second, 500)
	require.Len(t, ma.items, 3)
	require.Equal(t, float64(450), ma.average())

	// should kick out the second one
	ma.add(6*time.Second, 500)
	require.Len(t, ma.items, 3)
	require.Equal(t, float64(540), ma.average())

	for i := 0; i < 5; i++ {
		ma.add(2500*time.Millisecond, 1000)
	}

	require.Len(t, ma.items, 5)
	require.Equal(t, float64(1000), ma.average())
}

func TestClearNonces(t *testing.T) {
	lcs := getTestLocalCosigners(t, CosignerKeyTypeEd25519, 2, 3)
	cosigners := make([]Cosigner, len(lcs))
	for i, lc := range lcs {
		cosigners[i] = lc
	}

	cnc := CosignerNonceCache{
		threshold: 2,
		cache:     new(NonceCache),
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
		oneFound := false
		twoFound := false
		for _, cnr := range n.Nonces {
			if cnr.Cosigner == cosigners[1] {
				oneFound = true
			}
			if cnr.Cosigner == cosigners[2] {
				twoFound = true
			}
		}
		require.True(t, oneFound)
		require.True(t, twoFound)
	}

	cnc.ClearNonces(cosigners[1])

	require.Equal(t, 0, cnc.cache.Size())
}

type mockPruner struct {
	cache  *NonceCache
	count  int
	pruned int
	mu     sync.Mutex
}

func (mp *mockPruner) PruneNonces() int {
	pruned := mp.cache.PruneNonces()
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
	lcs := getTestLocalCosigners(t, CosignerKeyTypeEd25519, 2, 3)
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

	mp.cache = nonceCache.cache

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

	require.LessOrEqual(t, size, nonceCache.target(nonceCache.movingAverage.average()))

	count, pruned := mp.Result()

	require.Greater(t, count, 0, "count of pruning calls must be greater than 0")
	require.Equal(t, 0, pruned, "no nonces should have been pruned")
}

func TestNonceCacheExpiration(t *testing.T) {
	lcs := getTestLocalCosigners(t, CosignerKeyTypeEd25519, 2, 3)
	cosigners := make([]Cosigner, len(lcs))
	for i, lc := range lcs {
		cosigners[i] = lc
	}

	mp := &mockPruner{}

	noncesExpiration := 1000 * time.Millisecond
	getNoncesInterval := noncesExpiration / 5
	getNoncesTimeout := 10 * time.Millisecond
	nonceCache := NewCosignerNonceCache(
		cometlog.NewTMLogger(cometlog.NewSyncWriter(os.Stdout)),
		cosigners,
		&MockLeader{id: 1, leader: &ThresholdValidator{myCosigner: lcs[0]}},
		getNoncesInterval,
		getNoncesTimeout,
		noncesExpiration,
		2,
		mp,
	)

	mp.cache = nonceCache.cache

	ctx, cancel := context.WithCancel(context.Background())

	const loadN = 100
	// Load first set of 100 nonces
	nonceCache.LoadN(ctx, loadN)

	go nonceCache.Start(ctx)

	// Sleep for 1/2 nonceExpiration, no nonces should have expired yet
	time.Sleep(noncesExpiration / 2)

	// Load second set of 100 nonces
	nonceCache.LoadN(ctx, loadN)

	// Wait for first set of nonces to expire + wait for the interval to have run
	time.Sleep((noncesExpiration / 2) + getNoncesInterval)

	count, pruned := mp.Result()

	// we should have pruned at least 5 times after
	// waiting for 1200ms with a reconcile interval of 200ms
	require.GreaterOrEqual(t, count, 5)

	// we should have pruned only the first set of nonces
	// The second set of nonces should not have expired yet and we should not have load any more
	require.Equal(t, pruned, loadN)

	cancel()

	// the cache should be 100 (loadN) as the second set should not have expired.
	require.LessOrEqual(t, nonceCache.cache.Size(), loadN)
}

func TestNonceCachePrune(t *testing.T) {
	type testCase struct {
		name     string
		nonces   []*CachedNonce
		expected []*CachedNonce
	}

	now := time.Now()

	testCases := []testCase{
		{
			name:     "no nonces",
			nonces:   nil,
			expected: nil,
		},
		{
			name: "no expired nonces",
			nonces: []*CachedNonce{
				{
					UUID:       uuid.MustParse("d6ef381f-6234-432d-b204-d8957fe60360"),
					Expiration: now.Add(1 * time.Second),
				},
				{
					UUID:       uuid.MustParse("cdc3673d-7946-459a-b458-cbbde0eecd04"),
					Expiration: now.Add(2 * time.Second),
				},
				{
					UUID:       uuid.MustParse("38c6a201-0b8b-46eb-ab69-c7b2716d408e"),
					Expiration: now.Add(3 * time.Second),
				},
				{
					UUID:       uuid.MustParse("5caf5ab2-d460-430f-87fa-8ed2983ae8fb"),
					Expiration: now.Add(4 * time.Second),
				},
			},
			expected: []*CachedNonce{
				{
					UUID:       uuid.MustParse("d6ef381f-6234-432d-b204-d8957fe60360"),
					Expiration: now.Add(1 * time.Second),
				},
				{
					UUID:       uuid.MustParse("cdc3673d-7946-459a-b458-cbbde0eecd04"),
					Expiration: now.Add(2 * time.Second),
				},
				{
					UUID:       uuid.MustParse("38c6a201-0b8b-46eb-ab69-c7b2716d408e"),
					Expiration: now.Add(3 * time.Second),
				},
				{
					UUID:       uuid.MustParse("5caf5ab2-d460-430f-87fa-8ed2983ae8fb"),
					Expiration: now.Add(4 * time.Second),
				},
			},
		},
		{
			name: "first nonce is expired",
			nonces: []*CachedNonce{
				{
					UUID:       uuid.MustParse("d6ef381f-6234-432d-b204-d8957fe60360"),
					Expiration: now.Add(-1 * time.Second),
				},
				{
					UUID:       uuid.MustParse("cdc3673d-7946-459a-b458-cbbde0eecd04"),
					Expiration: now.Add(2 * time.Second),
				},
				{
					UUID:       uuid.MustParse("38c6a201-0b8b-46eb-ab69-c7b2716d408e"),
					Expiration: now.Add(3 * time.Second),
				},
				{
					UUID:       uuid.MustParse("5caf5ab2-d460-430f-87fa-8ed2983ae8fb"),
					Expiration: now.Add(4 * time.Second),
				},
			},
			expected: []*CachedNonce{
				{
					UUID:       uuid.MustParse("cdc3673d-7946-459a-b458-cbbde0eecd04"),
					Expiration: now.Add(2 * time.Second),
				},
				{
					UUID:       uuid.MustParse("38c6a201-0b8b-46eb-ab69-c7b2716d408e"),
					Expiration: now.Add(3 * time.Second),
				},
				{
					UUID:       uuid.MustParse("5caf5ab2-d460-430f-87fa-8ed2983ae8fb"),
					Expiration: now.Add(4 * time.Second),
				},
			},
		},
		{
			name: "all but last nonce expired",
			nonces: []*CachedNonce{
				{
					UUID:       uuid.MustParse("d6ef381f-6234-432d-b204-d8957fe60360"),
					Expiration: now.Add(-1 * time.Second),
				},
				{
					UUID:       uuid.MustParse("cdc3673d-7946-459a-b458-cbbde0eecd04"),
					Expiration: now.Add(-1 * time.Second),
				},
				{
					UUID:       uuid.MustParse("38c6a201-0b8b-46eb-ab69-c7b2716d408e"),
					Expiration: now.Add(-1 * time.Second),
				},
				{
					UUID:       uuid.MustParse("5caf5ab2-d460-430f-87fa-8ed2983ae8fb"),
					Expiration: now.Add(4 * time.Second),
				},
			},
			expected: []*CachedNonce{
				{
					UUID:       uuid.MustParse("5caf5ab2-d460-430f-87fa-8ed2983ae8fb"),
					Expiration: now.Add(4 * time.Second),
				},
			},
		},
		{
			name: "all nonces expired",
			nonces: []*CachedNonce{
				{
					UUID:       uuid.MustParse("d6ef381f-6234-432d-b204-d8957fe60360"),
					Expiration: now.Add(-1 * time.Second),
				},
				{
					UUID:       uuid.MustParse("cdc3673d-7946-459a-b458-cbbde0eecd04"),
					Expiration: now.Add(-1 * time.Second),
				},
				{
					UUID:       uuid.MustParse("38c6a201-0b8b-46eb-ab69-c7b2716d408e"),
					Expiration: now.Add(-1 * time.Second),
				},
				{
					UUID:       uuid.MustParse("5caf5ab2-d460-430f-87fa-8ed2983ae8fb"),
					Expiration: now.Add(-1 * time.Second),
				},
			},
			expected: nil,
		},
	}

	for _, tc := range testCases {
		nc := NonceCache{
			cache: tc.nonces,
		}

		pruned := nc.PruneNonces()

		require.Equal(t, len(tc.nonces)-len(tc.expected), pruned, tc.name)

		require.Equal(t, tc.expected, nc.cache, tc.name)
	}
}

func TestNonceCacheDemandSlow(t *testing.T) {
	lcs := getTestLocalCosigners(t, CosignerKeyTypeEd25519, 2, 3)
	cosigners := make([]Cosigner, len(lcs))
	for i, lc := range lcs {
		cosigners[i] = lc
	}

	nonceCache := NewCosignerNonceCache(
		cometlog.NewTMLogger(cometlog.NewSyncWriter(os.Stdout)),
		cosigners,
		&MockLeader{id: 1, leader: &ThresholdValidator{myCosigner: lcs[0]}},
		90*time.Millisecond,
		100*time.Millisecond,
		500*time.Millisecond,
		2,
		nil,
	)

	ctx, cancel := context.WithCancel(context.Background())

	go nonceCache.Start(ctx)

	for i := 0; i < 10; i++ {
		time.Sleep(200 * time.Millisecond)
		require.Greater(t, nonceCache.cache.Size(), 0)
		_, err := nonceCache.GetNonces([]Cosigner{cosigners[0], cosigners[1]})
		require.NoError(t, err)
	}

	cancel()

	require.LessOrEqual(t, nonceCache.cache.Size(), nonceCache.target(300))
}

func TestNonceCacheDemandSlowDefault(t *testing.T) {
	if testing.Short() {
		t.Skip()
	}
	lcs := getTestLocalCosigners(t, CosignerKeyTypeEd25519, 2, 3)
	cosigners := make([]Cosigner, len(lcs))
	for i, lc := range lcs {
		cosigners[i] = lc
	}

	nonceCache := NewCosignerNonceCache(
		cometlog.NewTMLogger(cometlog.NewSyncWriter(os.Stdout)),
		cosigners,
		&MockLeader{id: 1, leader: &ThresholdValidator{myCosigner: lcs[0]}},
		defaultGetNoncesInterval,
		defaultGetNoncesTimeout,
		defaultNonceExpiration,
		2,
		nil,
	)

	ctx, cancel := context.WithCancel(context.Background())

	go nonceCache.Start(ctx)

	for i := 0; i < 10; i++ {
		time.Sleep(7 * time.Second)
		require.Greater(t, nonceCache.cache.Size(), 0)
		_, err := nonceCache.GetNonces([]Cosigner{cosigners[0], cosigners[1]})
		require.NoError(t, err)
	}

	cancel()

	require.LessOrEqual(t, nonceCache.cache.Size(), nonceCache.target(60/7))
}
