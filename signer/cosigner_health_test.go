package signer_test

import (
	"os"
	"testing"

	"github.com/strangelove-ventures/horcrux/pkg/nodes"
	"github.com/strangelove-ventures/horcrux/signer"

	cometlog "github.com/cometbft/cometbft/libs/log"
	"github.com/stretchr/testify/require"
)

func TestCosignerHealth(t *testing.T) {
	ch := signer.NewCosignerHealth(
		cometlog.NewTMLogger(cometlog.NewSyncWriter(os.Stdout)),
		[]nodes.Cosigner{
			&nodes.RemoteCosigner{id: 2},
			&nodes.RemoteCosigner{id: 3},
			&nodes.RemoteCosigner{id: 4},
			&nodes.RemoteCosigner{id: 5},
		},
		&MockLeader{id: 1},
	)

	ch.rtt = map[int]int64{
		2: 200,
		3: -1,
		4: 100,
		5: 300,
	}

	fastest := ch.GetFastest()

	require.Len(t, fastest, 4)

	require.Equal(t, 4, fastest[0].GetIndex())
	require.Equal(t, 2, fastest[1].GetIndex())
}
