package signer

import (
	"context"
	"sort"
	"sync"
	"time"

	cometlog "github.com/cometbft/cometbft/libs/log"

	"github.com/strangelove-ventures/horcrux/v3/signer/proto"
)

const (
	pingInterval = 1 * time.Second
)

type CosignerHealth struct {
	logger    cometlog.Logger
	cosigners []Cosigner
	rtt       map[int]int64
	mu        sync.RWMutex

	leader Leader
}

func NewCosignerHealth(logger cometlog.Logger, cosigners []Cosigner, leader Leader) *CosignerHealth {
	return &CosignerHealth{
		logger:    logger,
		cosigners: cosigners,
		rtt:       make(map[int]int64),
		leader:    leader,
	}
}

func (ch *CosignerHealth) Reconcile(ctx context.Context) {
	if !ch.leader.IsLeader() {
		return
	}
	var wg sync.WaitGroup
	wg.Add(len(ch.cosigners))
	for _, cosigner := range ch.cosigners {
		if rc, ok := cosigner.(*RemoteCosigner); ok {
			go ch.updateRTT(ctx, rc, &wg)
		}
	}
	wg.Wait()
}

func (ch *CosignerHealth) Start(ctx context.Context) {
	ticker := time.NewTicker(pingInterval)
	for {
		ch.Reconcile(ctx)
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			// continue
		}
	}
}

func (ch *CosignerHealth) MarkUnhealthy(cosigner Cosigner) {
	ch.mu.Lock()
	defer ch.mu.Unlock()
	ch.rtt[cosigner.GetID()] = -1
}

func (ch *CosignerHealth) updateRTT(ctx context.Context, cosigner *RemoteCosigner, wg *sync.WaitGroup) {
	defer wg.Done()

	rtt := int64(-1)
	defer func() {
		ch.mu.Lock()
		defer ch.mu.Unlock()
		ch.rtt[cosigner.GetID()] = rtt
	}()
	start := time.Now()
	ctx, cancel := context.WithTimeout(ctx, 1*time.Second)
	defer cancel()

	_, err := cosigner.client.Ping(ctx, &proto.PingRequest{})
	if err != nil {
		ch.logger.Error("Failed to ping", "cosigner", cosigner.GetID(), "error", err)
		return
	}
	rtt = time.Since(start).Nanoseconds()
}

func (ch *CosignerHealth) GetFastest() []Cosigner {
	ch.mu.RLock()
	defer ch.mu.RUnlock()

	fastest := make([]Cosigner, len(ch.cosigners))
	copy(fastest, ch.cosigners)

	sort.Slice(fastest, func(i, j int) bool {
		rtt1, ok1 := ch.rtt[fastest[i].GetID()]
		rtt2, ok2 := ch.rtt[fastest[j].GetID()]
		if rtt1 == -1 || !ok1 {
			return false
		}
		if rtt2 == -1 || !ok2 {
			return true
		}
		return rtt1 < rtt2
	})

	return fastest
}
