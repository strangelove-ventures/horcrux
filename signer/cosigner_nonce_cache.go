package signer

import (
	"context"
	"fmt"
	"sort"
	"sync"
	"time"

	cometlog "github.com/cometbft/cometbft/libs/log"
	"github.com/google/uuid"
)

const (
	defaultGetNoncesInterval = 3 * time.Second
	defaultGetNoncesTimeout  = 4 * time.Second
	cachePreSize             = 10000
	nonceCacheExpiration     = 10 * time.Second // half of the local cosigner cache expiration
)

type CosignerNonceCache struct {
	logger    cometlog.Logger
	cosigners []Cosigner

	leader Leader

	lastReconcileNonces lastCount
	lastReconcileTime   time.Time
	noncesPerMinute     float64

	getNoncesInterval time.Duration
	getNoncesTimeout  time.Duration

	threshold uint8

	cache NonceCache

	pruner NonceCachePruner
}

type lastCount struct {
	count int
	mu    sync.RWMutex
}

func (lc *lastCount) Set(n int) {
	lc.mu.Lock()
	defer lc.mu.Unlock()
	lc.count = n
}

func (lc *lastCount) Inc() {
	lc.mu.Lock()
	defer lc.mu.Unlock()
	lc.count++
}

func (lc *lastCount) Get() int {
	lc.mu.RLock()
	defer lc.mu.RUnlock()
	return lc.count
}

type NonceCachePruner interface {
	PruneNonces()
}

type NonceCache struct {
	cache map[uuid.UUID]*CachedNonce
	mu    sync.RWMutex
}

func NewNonceCache() NonceCache {
	return NonceCache{
		cache: make(map[uuid.UUID]*CachedNonce, cachePreSize),
	}
}

func (nc *NonceCache) Size() int {
	nc.mu.RLock()
	defer nc.mu.RUnlock()
	return len(nc.cache)
}

func (nc *NonceCache) Get(uuid uuid.UUID) (*CachedNonce, bool) {
	nc.mu.RLock()
	defer nc.mu.RUnlock()
	cn, ok := nc.cache[uuid]
	return cn, ok
}

func (nc *NonceCache) Set(uuid uuid.UUID, cn *CachedNonce) {
	nc.mu.Lock()
	defer nc.mu.Unlock()
	nc.cache[uuid] = cn
}

func (nc *NonceCache) GetSortedByExpiration() []*CachedNonce {
	cns := make([]*CachedNonce, 0, len(nc.cache))
	for _, cn := range nc.cache {
		cns = append(cns, cn)
	}
	sort.Slice(cns, func(i, j int) bool {
		return cns[i].Expiration.Before(cns[j].Expiration)
	})
	return cns
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
	threshold uint8,
	pruner NonceCachePruner,
) *CosignerNonceCache {
	cnc := &CosignerNonceCache{
		logger:            logger,
		cache:             NewNonceCache(),
		cosigners:         cosigners,
		leader:            leader,
		getNoncesInterval: getNoncesInterval,
		getNoncesTimeout:  getNoncesTimeout,
		threshold:         threshold,
		pruner:            pruner,
	}
	if pruner == nil {
		cnc.pruner = cnc
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

func (cnc *CosignerNonceCache) reconcile(ctx context.Context) {
	// prune expired nonces
	cnc.pruner.PruneNonces()

	if !cnc.leader.IsLeader() {
		return
	}
	remainingNonces := cnc.cache.Size()
	timeSinceLastReconcile := time.Since(cnc.lastReconcileTime)

	// calculate nonces per minute
	noncesPerMin := float64(cnc.lastReconcileNonces.Get()-remainingNonces) / timeSinceLastReconcile.Minutes()
	if noncesPerMin < 0 {
		noncesPerMin = 0
	}

	if cnc.noncesPerMinute == 0 {
		// initialize nonces per minute for weighted average
		cnc.noncesPerMinute = noncesPerMin
	} else {
		// weighted average over last 4 intervals
		cnc.noncesPerMinute = (cnc.noncesPerMinute*3 + noncesPerMin) / 4
	}

	defer func() {

		cnc.lastReconcileNonces.Set(cnc.cache.Size())
		cnc.lastReconcileTime = time.Now()
	}()

	// calculate how many nonces we need to load to keep up with demand
	// load 120% the number of nonces we need to keep up with demand,
	// plus a couple seconds worth of nonces to account for nonce consumption during LoadN
	// plus 10 for padding

	target := int((cnc.noncesPerMinute/60)*cnc.getNoncesInterval.Seconds()*1.2) + int(cnc.noncesPerMinute/30) + 10
	additional := target - remainingNonces
	if additional <= 0 {
		// we're ahead of demand, don't load any more
		cnc.logger.Debug(
			"Cosigner nonce cache ahead of demand",
			"target", target,
			"remaining", remainingNonces,
			"noncesPerMin", cnc.noncesPerMinute,
		)
		return
	}

	cnc.logger.Debug(
		"Loading additional nonces to meet demand",
		"target", target,
		"remaining", remainingNonces,
		"additional", additional,
		"noncesPerMin", cnc.noncesPerMinute,
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

	expiration := time.Now().Add(nonceCacheExpiration)

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
			cnc.cache.Set(u, &nonce)
			added++
		}
	}
	cnc.logger.Debug("Loaded nonces", "desired", n, "added", added)
}

func (cnc *CosignerNonceCache) Start(ctx context.Context) {
	cnc.lastReconcileNonces.Set(cnc.cache.Size())
	cnc.lastReconcileTime = time.Now()

	ticker := time.NewTicker(cnc.getNoncesInterval)
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			cnc.reconcile(ctx)
		}
	}
}

func (cnc *CosignerNonceCache) GetNonces(fastestPeers []Cosigner) (*CosignerUUIDNonces, error) {
	cnc.cache.mu.Lock()
	defer cnc.cache.mu.Unlock()
CheckNoncesLoop:
	for _, cn := range cnc.cache.GetSortedByExpiration() {
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

		delete(cnc.cache.cache, cn.UUID)

		// all peers found
		return &CosignerUUIDNonces{
			UUID:   cn.UUID,
			Nonces: nonces,
		}, nil
	}

	// increment so it's taken into account in the nonce burn rate in the next reconciliation
	cnc.lastReconcileNonces.Inc()

	// no nonces found
	cosignerInts := make([]int, len(fastestPeers))
	for i, p := range fastestPeers {
		cosignerInts[i] = p.GetID()
	}
	return nil, fmt.Errorf("no nonces found involving cosigners %+v", cosignerInts)
}

func (cnc *CosignerNonceCache) PruneNonces() {
	cnc.cache.mu.Lock()
	defer cnc.cache.mu.Unlock()
	for u, cn := range cnc.cache.cache {
		if time.Now().After(cn.Expiration) {
			fmt.Printf("Pruning nonce %s\n", u)
			delete(cnc.cache.cache, u)
		}
	}
}

func (cnc *CosignerNonceCache) ClearNonces(cosigner Cosigner) {
	cnc.cache.mu.Lock()
	defer cnc.cache.mu.Unlock()
	for u, cn := range cnc.cache.cache {
		deleteID := -1
		for i, n := range cn.Nonces {
			if n.Cosigner.GetID() == cosigner.GetID() {
				// remove cosigner from this nonce.
				deleteID = i
				break
			}
		}
		if deleteID >= 0 {
			if len(cn.Nonces)-1 < int(cnc.threshold) {
				// If cosigners on this nonce drops below threshold, delete it as it's no longer usable
				delete(cnc.cache.cache, u)
			} else {
				cn.Nonces = append(cn.Nonces[:deleteID], cn.Nonces[deleteID+1:]...)
			}
		}
	}
}

func (cnc *CosignerNonceCache) ClearAllNonces() {
	cnc.cache.mu.Lock()
	defer cnc.cache.mu.Unlock()
	cnc.cache.cache = make(map[uuid.UUID]*CachedNonce, cachePreSize)
}
