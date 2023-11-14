package signer

import (
	"context"
	"sort"
	"sync"
	"time"

	"github.com/strangelove-ventures/horcrux/signer/proto"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

const (
	pingInterval = 5 * time.Second
)

type CosignerHealth struct {
	cosigners []Cosigner
	rtt       map[int]int64
	mu        sync.RWMutex

	leader Leader
}

func NewCosignerHealth(cosigners []Cosigner, leader Leader) *CosignerHealth {
	return &CosignerHealth{
		cosigners: cosigners,
		rtt:       make(map[int]int64),
		leader:    leader,
	}
}

func (ch *CosignerHealth) Start(ctx context.Context) {
	ticker := time.NewTicker(pingInterval)
	for {
		if ch.leader.IsLeader() {
			for _, cosigner := range ch.cosigners {
				go ch.updateRTT(ctx, cosigner)
			}
		}
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			// continue
		}
	}
}

func (ch *CosignerHealth) updateRTT(ctx context.Context, cosigner Cosigner) {
	var rtt int64
	defer func() {
		ch.mu.Lock()
		defer ch.mu.Unlock()
		ch.rtt[cosigner.GetID()] = rtt
	}()
	start := time.Now()
	conn, err := grpc.Dial(cosigner.GetAddress(), grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		return
	}
	client := proto.NewCosignerClient(conn)
	_, err = client.Ping(ctx, &proto.PingRequest{})
	if err != nil {
		rtt = -1
	} else {
		rtt = time.Since(start).Nanoseconds()
	}
}

func (ch *CosignerHealth) GetFastest(n int) []Cosigner {
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

	return fastest[:n]
}
