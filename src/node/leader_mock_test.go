package node_test

import (
	"sync"

	"github.com/strangelove-ventures/horcrux/src/cosigner"
	"github.com/strangelove-ventures/horcrux/src/node"
	"github.com/strangelove-ventures/horcrux/src/types"
)

var _ node.ILeader = (*MockLeader)(nil)

type MockThresholdValidator struct {
	myCosigner *cosigner.LocalCosigner
}

type MockLeader struct {
	id     int
	mu     sync.Mutex
	leader *node.ThresholdValidator
}

func (m *MockLeader) IsLeader() bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.leader != nil && m.GetLeader() == m.id
}

func (m *MockLeader) SetLeader(tv *node.ThresholdValidator) {
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
