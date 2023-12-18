package signer

import (
	"context"
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	cometlog "github.com/cometbft/cometbft/libs/log"
	"github.com/google/uuid"
)

const (
	defaultGetNoncesInterval = 3 * time.Second
	defaultGetNoncesTimeout  = 4 * time.Second
	defaultNonceExpiration   = 10 * time.Second // half of the local cosigner cache expiration
	nonceOverallocation      = 1.5
)

type CosignerNonceCache struct {
	logger    cometlog.Logger
	cosigners []Cosigner

	leader Leader

	lastReconcileNonces atomic.Uint64
	lastReconcileTime   time.Time

	getNoncesInterval time.Duration
	getNoncesTimeout  time.Duration
	nonceExpiration   time.Duration

	threshold uint8

	cache *NonceCache

	pruner NonceCachePruner

	movingAverage *movingAverage

	empty chan struct{}
}

type movingAverageItem struct {
	timeSinceLastReconcile time.Duration
	noncesPerMinute        float64
}

type movingAverage struct {
	items  []movingAverageItem
	period time.Duration
}

func newMovingAverage(period time.Duration) *movingAverage {
	return &movingAverage{period: period}
}

func (m *movingAverage) add(
	timeSinceLastReconcile time.Duration,
	noncesPerMinute float64,
) {
	duration := timeSinceLastReconcile
	keep := len(m.items) - 1
	for i, e := range m.items {
		duration += e.timeSinceLastReconcile
		if duration >= m.period {
			keep = i
			break
		}
	}
	m.items = append(
		[]movingAverageItem{{timeSinceLastReconcile: timeSinceLastReconcile, noncesPerMinute: noncesPerMinute}},
		m.items[:keep+1]...,
	)
}

func (m *movingAverage) average() float64 {
	weightedSum := float64(0)
	duration := float64(0)

	for _, e := range m.items {
		d := float64(e.timeSinceLastReconcile)
		weightedSum += e.noncesPerMinute * d
		duration += d
	}

	return weightedSum / duration
}

type NonceCachePruner interface {
	PruneNonces() int
}

type NonceCache struct {
	cache []*CachedNonce
	mu    sync.RWMutex
}

func (nc *NonceCache) Size() int {
	nc.mu.RLock()
	defer nc.mu.RUnlock()
	return len(nc.cache)
}

func (nc *NonceCache) Add(cn *CachedNonce) {
	nc.mu.Lock()
	defer nc.mu.Unlock()
	nc.cache = append(nc.cache, cn)
}

func (nc *NonceCache) Delete(index int) {
	nc.cache = append(nc.cache[:index], nc.cache[index+1:]...)
}

func (nc *NonceCache) PruneNonces() int {
	nc.mu.Lock()
	defer nc.mu.Unlock()
	nonExpiredIndex := -1
	for i := 0; i < len(nc.cache); i++ {
		if time.Now().Before(nc.cache[i].Expiration) {
			nonExpiredIndex = i
			break
		}
	}

	var deleteCount int
	if nonExpiredIndex == -1 {
		// No non-expired nonces, delete everything
		deleteCount = len(nc.cache)
		nc.cache = nil
	} else {
		// Prune everything up to the non-expired nonce
		deleteCount = nonExpiredIndex
		nc.cache = nc.cache[nonExpiredIndex:]
	}
	return deleteCount
}

type CosignerNoncesRel struct {
	Cosigner Cosigner
	Nonces   CosignerNonces
}

type CachedNonceSingle struct {
	Cosigner Cosigner
	Nonces   CosignerUUIDNoncesMultiple
}

type CachedNonce struct {
	// UUID identifying this collection of nonces
	UUID uuid.UUID

	// Expiration time of this nonce
	Expiration time.Time

	// Cached nonces, cosigners which have this nonce in their metadata, ready to sign
	Nonces []CosignerNoncesRel
}

func NewCosignerNonceCache(
	logger cometlog.Logger,
	cosigners []Cosigner,
	leader Leader,
	getNoncesInterval time.Duration,
	getNoncesTimeout time.Duration,
	nonceExpiration time.Duration,
	threshold uint8,
	pruner NonceCachePruner,
) *CosignerNonceCache {
	cnc := &CosignerNonceCache{
		logger:            logger,
		cosigners:         cosigners,
		leader:            leader,
		getNoncesInterval: getNoncesInterval,
		getNoncesTimeout:  getNoncesTimeout,
		nonceExpiration:   nonceExpiration,
		threshold:         threshold,
		pruner:            pruner,
		cache:             new(NonceCache),
		// buffer up to 1000 empty events so that we don't ever block
		empty:         make(chan struct{}, 1000),
		movingAverage: newMovingAverage(4 * getNoncesInterval), // weighted average over 4 intervals
	}
	// the only time pruner is expected to be non-nil is during tests, otherwise we use the cache logic.
	if pruner == nil {
		cnc.pruner = cnc.cache
	}

	return cnc
}

func (cnc *CosignerNonceCache) getUuids(n int) []uuid.UUID {
	uuids := make([]uuid.UUID, n)
	for i := 0; i < n; i++ {
		uuids[i] = uuid.New()
	}
	return uuids
}

func (cnc *CosignerNonceCache) target(noncesPerMinute float64) int {
	t := int((noncesPerMinute / 60) *
		((cnc.getNoncesInterval.Seconds() * nonceOverallocation) +
			cnc.getNoncesTimeout.Seconds()))
	if t <= 0 {
		return 1 // always target at least one nonce ready
	}
	return t
}

func (cnc *CosignerNonceCache) reconcile(ctx context.Context) {
	// prune expired nonces
	pruned := cnc.pruner.PruneNonces()

	if !cnc.leader.IsLeader() {
		return
	}
	remainingNonces := cnc.cache.Size()
	timeSinceLastReconcile := time.Since(cnc.lastReconcileTime)

	lastReconcileNonces := cnc.lastReconcileNonces.Load()
	// calculate nonces per minute
	noncesPerMin := float64(int(lastReconcileNonces)-remainingNonces-pruned) / timeSinceLastReconcile.Minutes()
	if noncesPerMin < 0 {
		noncesPerMin = 0
	}

	cnc.movingAverage.add(timeSinceLastReconcile, noncesPerMin)

	// calculate how many nonces we need to load to keep up with demand
	// load 120% the number of nonces we need to keep up with demand,
	// plus a couple seconds worth of nonces to account for nonce consumption during LoadN
	// plus 10 for padding

	avgNoncesPerMin := cnc.movingAverage.average()
	t := cnc.target(avgNoncesPerMin)
	additional := t - remainingNonces

	defer func() {
		cnc.lastReconcileNonces.Store(uint64(remainingNonces + additional))
		cnc.lastReconcileTime = time.Now()
	}()

	if additional <= 0 {
		additional = 0
		// we're ahead of demand, don't load any more
		cnc.logger.Debug(
			"Cosigner nonce cache ahead of demand",
			"target", t,
			"remaining", remainingNonces,
			"nonces_per_min", noncesPerMin,
			"avg_nonces_per_min", avgNoncesPerMin,
		)
		return
	}

	cnc.logger.Debug(
		"Loading additional nonces to meet demand",
		"target", t,
		"remaining", remainingNonces,
		"additional", additional,
		"nonces_per_min", noncesPerMin,
		"avg_nonces_per_min", avgNoncesPerMin,
	)

	cnc.LoadN(ctx, additional)
}

func (cnc *CosignerNonceCache) LoadN(ctx context.Context, n int) {
	if n == 0 {
		return
	}
	uuids := cnc.getUuids(n)
	nonces := make([]*CachedNonceSingle, len(cnc.cosigners))
	var wg sync.WaitGroup
	wg.Add(len(cnc.cosigners))

	expiration := time.Now().Add(cnc.nonceExpiration)

	for i, p := range cnc.cosigners {
		i := i
		p := p
		go func() {
			defer wg.Done()
			ctx, cancel := context.WithTimeout(ctx, cnc.getNoncesTimeout)
			defer cancel()

			peerStartTime := time.Now()
			n, err := p.GetNonces(ctx, uuids)
			if err != nil {
				// Significant missing shares may lead to signature failure
				missedNonces.WithLabelValues(p.GetAddress()).Add(float64(1))
				totalMissedNonces.WithLabelValues(p.GetAddress()).Inc()

				cnc.logger.Error("Failed to get nonces from peer", "peer", p.GetID(), "error", err)
				return
			}

			missedNonces.WithLabelValues(p.GetAddress()).Set(0)
			timedCosignerNonceLag.WithLabelValues(p.GetAddress()).Observe(time.Since(peerStartTime).Seconds())

			nonces[i] = &CachedNonceSingle{
				Cosigner: p,
				Nonces:   n,
			}
		}()
	}
	wg.Wait()
	added := 0
	for i, u := range uuids {
		nonce := CachedNonce{
			UUID:       u,
			Expiration: expiration,
		}
		num := uint8(0)
		for _, n := range nonces {
			if n == nil {
				continue
			}
			num++
			nonce.Nonces = append(nonce.Nonces, CosignerNoncesRel{
				Cosigner: n.Cosigner,
				Nonces:   n.Nonces[i].Nonces,
			})
		}
		if num >= cnc.threshold {
			cnc.cache.Add(&nonce)
			added++
		}
	}
	cnc.logger.Debug("Loaded nonces", "desired", n, "added", added)
}

func (cnc *CosignerNonceCache) Start(ctx context.Context) {
	cnc.lastReconcileNonces.Store(uint64(cnc.cache.Size()))
	cnc.lastReconcileTime = time.Now()

	timer := time.NewTimer(cnc.getNoncesInterval)
	for {
		select {
		case <-ctx.Done():
			return
		case <-timer.C:
		case <-cnc.empty:
			// clear out channel
			for len(cnc.empty) > 0 {
				<-cnc.empty
			}
		}
		cnc.reconcile(ctx)
		timer.Reset(cnc.getNoncesInterval)
	}
}

func (cnc *CosignerNonceCache) GetNonces(fastestPeers []Cosigner) (*CosignerUUIDNonces, error) {
	cnc.cache.mu.Lock()
	defer cnc.cache.mu.Unlock()
CheckNoncesLoop:
	for i, cn := range cnc.cache.cache {
		var nonces CosignerNonces
		for _, p := range fastestPeers {
			found := false
			for _, n := range cn.Nonces {
				if n.Cosigner.GetID() == p.GetID() {
					found = true
					nonces = append(nonces, n.Nonces...)
					break
				}
			}
			if !found {
				// this set of nonces doesn't have the peer we need
				continue CheckNoncesLoop
			}
		}

		// remove this set of nonces from the cache
		cnc.cache.Delete(i)

		if len(cnc.cache.cache) == 0 && len(cnc.empty) == 0 {
			cnc.logger.Debug("Nonce cache is empty, triggering reload")
			cnc.empty <- struct{}{}
		}

		// all peers found
		return &CosignerUUIDNonces{
			UUID:   cn.UUID,
			Nonces: nonces,
		}, nil
	}

	// increment so it's taken into account in the nonce burn rate in the next reconciliation
	cnc.lastReconcileNonces.Add(1)

	// no nonces found
	cosignerInts := make([]int, len(fastestPeers))
	for i, p := range fastestPeers {
		cosignerInts[i] = p.GetID()
	}
	return nil, fmt.Errorf("no nonces found involving cosigners %+v", cosignerInts)
}

func (cnc *CosignerNonceCache) ClearNonces(cosigner Cosigner) {
	cnc.cache.mu.Lock()
	defer cnc.cache.mu.Unlock()
	for i := 0; i < len(cnc.cache.cache); i++ {
		cn := cnc.cache.cache[i]

		deleteID := -1
		for j, n := range cn.Nonces {
			if n.Cosigner.GetID() == cosigner.GetID() {
				// remove cosigner from this nonce.
				deleteID = j
				break
			}
		}
		if deleteID >= 0 {
			if len(cn.Nonces)-1 < int(cnc.threshold) {
				// If cosigners on this nonce drops below threshold, delete it as it's no longer usable
				cnc.cache.Delete(i)
				i--
			} else {
				cn.Nonces = append(cn.Nonces[:deleteID], cn.Nonces[deleteID+1:]...)
			}
		}
	}
}
