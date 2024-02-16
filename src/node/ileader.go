package node

import "github.com/strangelove-ventures/horcrux/src/types"

// ILeader is an interface for the detecting if the current cosigner is the leader and performing leader actions.
// The leader is responsible for sharing the last signed state with the other cosigners.
// The leader is also responsible for detecting if the node is the leader.
// TODO: The leader is rresponsible for starting the signing process.
// BasciaConsensus Algorithm for the ThresholdValidator.
type ILeader interface {
	// IsLeader returns true if the cosigner is the leader otherwise false.
	IsLeader() bool

	// ShareSigned shares the last signed state with the other cosigners.
	ShareSigned(lss types.ChainSignStateConsensus) error

	// Get current leader
	GetLeader() int

	// Sign block
	// SignBlock(block types.Block) error
}
