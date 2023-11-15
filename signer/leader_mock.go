package signer

import (
	"sync"
)

var _ Leader = (*MockLeader)(nil)

type MockLeader struct {
	id int

	mu     sync.Mutex
	leader *ThresholdValidator
}

func (m *MockLeader) IsLeader() bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.leader != nil && m.leader.myCosigner.GetID() == m.id
}

func (m *MockLeader) SetLeader(tv *ThresholdValidator) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.leader = tv
}

func (m *MockLeader) GetLeader() int {
	return m.id
}

func (m *MockLeader) ShareSigned(_ ChainSignStateConsensus) error {
	return nil
}
