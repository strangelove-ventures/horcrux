package types

import (
	"time"

	"github.com/strangelove-ventures/horcrux/proto/strangelove/proto"

	//	"github.com/strangelove-ventures/horcrux/src/proto"

	cometproto "github.com/cometbft/cometbft/proto/tendermint/types"
	comet "github.com/cometbft/cometbft/types"
)

/*
	type Block struct {
		HRST
		SignBytes []byte
		Timestamp time.Time
	}
*/
type Block struct {
	Height    int64
	Round     int64
	Step      int8
	SignBytes []byte
	Timestamp time.Time
}

func (block Block) GetHRS() HRS {
	return HRS{
		Height: block.Height,
		Round:  block.Round,
		Step:   block.Step,
	}
}

func (block Block) ToHRST() HRST {
	return HRST{
		Height:    block.Height,
		Round:     block.Round,
		Step:      block.Step,
		Timestamp: block.Timestamp.UnixNano(),
	}
}

func (block Block) ToProto() *proto.Block {
	return &proto.Block{
		Height:    block.Height,
		Round:     block.Round,
		Step:      int32(block.Step),
		SignBytes: block.SignBytes,
		Timestamp: block.Timestamp.UnixNano(),
	}
}

func BlockFromProto(block *proto.Block) Block {
	return Block{
		// HRST: HRST{
		Height: block.Height,
		Round:  block.Round,
		Step:   int8(block.Step),
		// },
		SignBytes: block.SignBytes,
		Timestamp: time.Unix(0, block.Timestamp),
	}
}

const (
	StepPropose   int8 = 1
	StepPrevote   int8 = 2
	StepPrecommit int8 = 3
	blocksTocache      = 3
)

func SignType(step int8) string {
	switch step {
	case StepPropose:
		return "proposal"
	case StepPrevote:
		return "prevote"
	case StepPrecommit:
		return "precommit"
	default:
		return "unknown"
	}
}

func CanonicalVoteToStep(vote *cometproto.CanonicalVote) int8 {
	switch vote.Type {
	case cometproto.PrevoteType:
		return StepPrevote
	case cometproto.PrecommitType:
		return StepPrecommit
	default:
		panic("Unknown vote type")
	}
}

func VoteToStep(vote *cometproto.Vote) int8 {
	switch vote.Type {
	case cometproto.PrevoteType:
		return StepPrevote
	case cometproto.PrecommitType:
		return StepPrecommit
	default:
		panic("Unknown vote type")
	}
}

func VoteToBlock(chainID string, vote *cometproto.Vote) Block {
	return Block{
		Height:    vote.Height,
		Round:     int64(vote.Round),
		Step:      VoteToStep(vote),
		SignBytes: comet.VoteSignBytes(chainID, vote),
		Timestamp: vote.Timestamp,
	}
}

func ProposalToStep(_ *cometproto.Proposal) int8 {
	return StepPropose
}

func ProposalToBlock(chainID string, proposal *cometproto.Proposal) Block {
	return Block{
		Height:    proposal.Height,
		Round:     int64(proposal.Round),
		Step:      ProposalToStep(proposal),
		SignBytes: comet.ProposalSignBytes(chainID, proposal),
		Timestamp: proposal.Timestamp,
	}
}

func StepToType(step int8) cometproto.SignedMsgType {
	switch step {
	case StepPropose:
		return cometproto.ProposalType
	case StepPrevote:
		return cometproto.PrevoteType
	case StepPrecommit:
		return cometproto.PrecommitType
	default:
		panic("Unknown step")
	}
}
