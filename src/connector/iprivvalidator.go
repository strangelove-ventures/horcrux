package connector

import (
	"context"
	"time"

	"github.com/strangelove-ventures/horcrux/src/types"
)

// IPrivValidator is a wrapper for tendermint IPrivValidator,
// with additional Stop method for safe shutdown.
type IPrivValidator interface {
	Sign(ctx context.Context, chainID string, block types.Block) ([]byte, time.Time, error)
	GetPubKey(ctx context.Context, chainID string) ([]byte, error)
	Stop()
}
