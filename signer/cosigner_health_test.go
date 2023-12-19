package signer

import (
	"os"
	"sync"
	"testing"

	cometlog "github.com/cometbft/cometbft/libs/log"
	"github.com/strangelove-ventures/horcrux/pkg/nodes"
	"github.com/strangelove-ventures/horcrux/pkg/types"
	"github.com/stretchr/testify/require"
)

var _ Leader = (*MockLeader)(nil)

type MockThresholdValidator struct {
	myCosigner *nodes.LocalCosigner
}

type MockLeader struct {
	id int

	mu     sync.Mutex
	leader *MockThresholdValidator
}

func (m *MockLeader) IsLeader() bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.leader != nil && m.leader.myCosigner.GetIndex() == m.id
}

func (m *MockLeader) SetLeader(tv *MockThresholdValidator) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.leader = tv
}

func (m *MockLeader) GetLeader() int {
	return m.id
}

func (m *MockLeader) ShareSigned(_ types.ChainSignStateConsensus) error {
	return nil
}

func TestCosignerHealth(t *testing.T) {

	cosigner2, _ := nodes.NewRemoteCosigner(2, "")
	cosigner3, _ := nodes.NewRemoteCosigner(3, "")
	cosigner4, _ := nodes.NewRemoteCosigner(4, "")
	cosigner5, _ := nodes.NewRemoteCosigner(5, "")
	ch := NewCosignerHealth(
		cometlog.NewTMLogger(cometlog.NewSyncWriter(os.Stdout)),
		[]nodes.Cosigner{
			cosigner2,
			cosigner3,
			cosigner4,
			cosigner5,
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
