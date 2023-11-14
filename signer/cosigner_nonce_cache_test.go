package signer

import (
	"context"
	"os"
	"testing"
	"time"

	cometlog "github.com/cometbft/cometbft/libs/log"
	"github.com/stretchr/testify/require"
)

func TestNonceCacheDemand(t *testing.T) {
	lcs, _ := getTestLocalCosigners(t, 2, 3)
	cosigners := make([]Cosigner, len(lcs))
	for i, lc := range lcs {
		cosigners[i] = lc
	}

	nonceCache := NewCosignerNonceCache(
		cometlog.NewTMLogger(cometlog.NewSyncWriter(os.Stdout)),
		cosigners,
		&MockLeader{id: 1, leader: &ThresholdValidator{myCosigner: lcs[0]}},
		500*time.Millisecond,
		100*time.Millisecond,
	)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go nonceCache.Start(ctx)

	for i := 0; i < 3000; i++ {
		nonceCache.GetNonces(ctx, []Cosigner{cosigners[0], cosigners[1]})
		time.Sleep(10 * time.Millisecond)
		require.Greater(t, len(nonceCache.readyNonces), 0)
	}

	require.Greater(t, len(nonceCache.readyNonces), 0)

	target := int(nonceCache.noncesPerMinute * .01)
	require.LessOrEqual(t, len(nonceCache.readyNonces), target)
}
