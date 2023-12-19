package signer_test

import (
	"sync"

	"github.com/strangelove-ventures/horcrux/pkg/nodes"
	"github.com/strangelove-ventures/horcrux/pkg/types"
	"github.com/strangelove-ventures/horcrux/signer"
)

var _ signer.Leader = (*MockLeader)(nil)

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
