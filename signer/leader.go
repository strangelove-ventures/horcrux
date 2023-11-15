package signer

// Leader is an interface for the detecting if the current cosigner is the leader and performing leader actions.
type Leader interface {
	// IsLeader returns true if the cosigner is the leader.
	IsLeader() bool

	// ShareSigned shares the last signed state with the other cosigners.
	ShareSigned(lss ChainSignStateConsensus) error

	// Get current leader
	GetLeader() int
}
