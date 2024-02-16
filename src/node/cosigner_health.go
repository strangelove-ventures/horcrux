package node

import (
	"context"
	"sort"
	"sync"
	"time"

	"github.com/strangelove-ventures/horcrux/src/cosigner"

	cometlog "github.com/cometbft/cometbft/libs/log"
	"github.com/strangelove-ventures/horcrux/proto/strangelove/proto"
	// "github.com/strangelove-ventures/horcrux/src/proto"
)

const (
	pingInterval = 1 * time.Second
)

type CosignerHealth struct {
	logger    cometlog.Logger
	cosigners []ICosigner
	rtt       map[int]int64
	mu        sync.RWMutex

	leader ILeader
}

func NewCosignerHealth(logger cometlog.Logger, cosigners []ICosigner, leader ILeader) *CosignerHealth {
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
	for _, remotecosigner := range ch.cosigners {
		if rc, ok := remotecosigner.(*cosigner.CosignerClient); ok {
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

func (ch *CosignerHealth) MarkUnhealthy(cosigner ICosigner) {
	ch.mu.Lock()
	defer ch.mu.Unlock()
	ch.rtt[cosigner.GetIndex()] = -1
}

func (ch *CosignerHealth) updateRTT(ctx context.Context, cosigner *cosigner.CosignerClient, wg *sync.WaitGroup) {
	defer wg.Done()

	rtt := int64(-1)
	defer func() {
		ch.mu.Lock()
		defer ch.mu.Unlock()
		ch.rtt[cosigner.GetIndex()] = rtt
	}()
	start := time.Now()
	ctx, cancel := context.WithTimeout(ctx, 1*time.Second)
	defer cancel()

	_, err := cosigner.Client.Ping(ctx, &proto.PingRequest{})
	if err != nil {
		ch.logger.Error("Failed to ping", "cosigner", cosigner.GetIndex(), "error", err)
		return
	}
	rtt = time.Since(start).Nanoseconds()
}

func (ch *CosignerHealth) GetFastest() []ICosigner {
	ch.mu.RLock()
	defer ch.mu.RUnlock()

	fastest := make([]ICosigner, len(ch.cosigners))
	copy(fastest, ch.cosigners)

	sort.Slice(fastest, func(i, j int) bool {
		rtt1, ok1 := ch.rtt[fastest[i].GetIndex()]
		rtt2, ok2 := ch.rtt[fastest[j].GetIndex()]
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
