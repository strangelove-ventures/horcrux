package signer

import (
	"os"
	"testing"

	"github.com/stretchr/testify/require"

	cometlog "github.com/cometbft/cometbft/libs/log"
)

func TestCosignerHealth(t *testing.T) {
	ch := NewCosignerHealth(
		cometlog.NewTMLogger(cometlog.NewSyncWriter(os.Stdout)),
		[]Cosigner{
			&RemoteCosigner{id: 2},
			&RemoteCosigner{id: 3},
			&RemoteCosigner{id: 4},
			&RemoteCosigner{id: 5},
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

	require.Equal(t, 4, fastest[0].GetID())
	require.Equal(t, 2, fastest[1].GetID())
}
