package signer

// Leader is an interface for the detecting if the current node/validator/cosigner is
// the leader and performing leader actions.
type Leader interface {
	// IsLeader returns true if the cosigner is the leader.
	IsLeader() bool

	// SignBlock asks the leader to manage the signing of a block.
	SignBlock(ValidatorSignBlockRequest) (*ValidatorSignBlockResponse, error)

	// ShareSigned shares the last signed state with the other cosigners.
	ShareSigned(lss ChainSignStateConsensus) error
}
