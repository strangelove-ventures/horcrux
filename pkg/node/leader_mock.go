package node

// MockLeader is a "helper" mathod for use with testing.
import (
	"errors"
	"sync"
	"time"

	"github.com/strangelove-ventures/horcrux/pkg/types"
)

var _ ILeader = (*MockLeader)(nil)

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

func (m *MockLeader) SignBlock(req ValidatorSignBlockRequest) (*ValidatorSignBlockResponse, error) {
	var l *ThresholdValidator
	for i := 0; i < 30; i++ {
		m.mu.Lock()
		l = m.leader
		m.mu.Unlock()
		if l != nil {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}

	if l == nil {
		return nil, errors.New("timed out waiting for leader election to complete")
	}

	block := &Block{
		Height:    req.Block.Height,
		Round:     req.Block.Round,
		Step:      req.Block.Step,
		SignBytes: req.Block.SignBytes,
		Timestamp: req.Block.Timestamp,
	}
	res, _, err := l.SignBlock(req.ChainID, block)
	if err != nil {
		return nil, err
	}
	return &ValidatorSignBlockResponse{
		Signature: res,
	}, nil
}

func (m *MockLeader) ShareSigned(_ types.ChainSignStateConsensus) error {
	return nil
}
