package signer

import (
	"context"
	"sync"
	"time"

	cometlog "github.com/cometbft/cometbft/libs/log"
	"github.com/google/uuid"
)

const defaultGetNoncesInterval = 5 * time.Second
const defaultGetNoncesTimeout = 4 * time.Second

type CosignerNonceCache struct {
	logger      cometlog.Logger
	cosigners   []Cosigner
	readyNonces chan *CosignerUUIDNonces

	leader Leader

	lastReconcileNonces int
	lastReconcileTime   time.Time
	noncesPerMinute     float64

	getNoncesInterval time.Duration
	getNoncesTimeout  time.Duration
}

func NewCosignerNonceCache(
	logger cometlog.Logger,
	cosigners []Cosigner,
	leader Leader,
	getNoncesInterval time.Duration,
	getNoncesTimeout time.Duration,
) *CosignerNonceCache {
	return &CosignerNonceCache{
		logger:            logger,
		readyNonces:       make(chan *CosignerUUIDNonces, 10000),
		cosigners:         cosigners,
		leader:            leader,
		getNoncesInterval: getNoncesInterval,
		getNoncesTimeout:  getNoncesTimeout,
	}
}

func (cnc *CosignerNonceCache) getUuids(n int) []uuid.UUID {
	uuids := make([]uuid.UUID, n)
	for i := 0; i < n; i++ {
		uuids[i] = uuid.New()
	}
	return uuids
}

func (cnc *CosignerNonceCache) reconcile(ctx context.Context) {
	cnc.logger.Debug("Reconciling nonces")
	remainingNonces := len(cnc.readyNonces)
	timeSinceLastReconcile := time.Since(cnc.lastReconcileTime)

	// calculate nonces per minute
	noncesPerMin := float64(cnc.lastReconcileNonces-remainingNonces) / timeSinceLastReconcile.Minutes()

	if cnc.noncesPerMinute == 0 {
		// initialize nonces per minute for weighted average
		cnc.noncesPerMinute = noncesPerMin
	} else {
		// weighted average over last 2 intervals
		cnc.noncesPerMinute = (cnc.noncesPerMinute + noncesPerMin) / 2
	}

	defer func() {
		cnc.lastReconcileNonces = len(cnc.readyNonces)
		cnc.lastReconcileTime = time.Now()
	}()

	// calculate how many nonces we need to load to keep up with demand
	// load 120% the number of nonces we need to keep up with demand,
	// plus 10 for padding

	target := int((cnc.noncesPerMinute/60)*cnc.getNoncesInterval.Seconds()*1.2) + 10
	additional := target - remainingNonces
	if additional < 0 {
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
	uuids := cnc.getUuids(n)
	nonces := make([]CosignerUUIDNoncesMultiple, len(cnc.cosigners))
	var wg sync.WaitGroup
	wg.Add(len(cnc.cosigners))
	for i, p := range cnc.cosigners {
		i := i
		p := p
		go func() {
			defer wg.Done()
			ctx, cancel := context.WithTimeout(ctx, cnc.getNoncesTimeout)
			defer cancel()
			n, err := p.GetNonces(ctx, uuids)
			if err != nil {
				cnc.logger.Error("Failed to get nonces from peer", "peer", p.GetID(), "error", err)
				return
			}
			nonces[i] = n
		}()
	}
	wg.Wait()
	for i, u := range uuids {
		nonce := &CosignerUUIDNonces{
			UUID: u,
		}
		for _, n := range nonces {
			if n == nil {
				continue
			}
			nonce.Nonces = append(nonce.Nonces, n[i].Nonces...)
		}
		cnc.readyNonces <- nonce
	}
	cnc.logger.Debug("Loaded nonces", "count", n)
}

func (cnc *CosignerNonceCache) Start(ctx context.Context) {
	// tiered startup to quickly bootstrap nonces for immediate signing
	for i := 1; i < 10; i++ {
		cnc.LoadN(ctx, i*20)
	}

	cnc.lastReconcileNonces = len(cnc.readyNonces)
	cnc.lastReconcileTime = time.Now()

	ticker := time.NewTicker(cnc.getNoncesInterval)
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if cnc.leader.IsLeader() {
				cnc.reconcile(ctx)
			}
		}
	}
}

func (cnc *CosignerNonceCache) GetNonces(ctx context.Context, fastestPeers []Cosigner) (*CosignerUUIDNonces, error) {
CheckNoncesLoop:
	for {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case out := <-cnc.readyNonces:
			for _, p := range fastestPeers {
				found := false
				for _, n := range out.Nonces {
					if n.SourceID == p.GetID() {
						found = true
						break
					}
				}
				if !found {
					// this set of nonces doesn't have the peer we need
					// TODO this uuid should be discarded on all cosigners
					// send delete request via raft?
					continue CheckNoncesLoop
				}
			}

			// all peers found
			return out, nil
		}
	}
}
