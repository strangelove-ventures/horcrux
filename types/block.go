package types

import (
	"time"

	cometproto "github.com/strangelove-ventures/horcrux/v3/comet/proto/types"
	grpccosigner "github.com/strangelove-ventures/horcrux/v3/grpc/cosigner"
)

type BlockID struct {
	Hash          []byte
	PartSetHeader PartSetHeader
}

func (bid *BlockID) ToCanonical() *cometproto.CanonicalBlockID {
	if bid == nil || (len(bid.Hash) == 0 && bid.PartSetHeader.Total == 0 && len(bid.PartSetHeader.Hash) == 0) {
		return nil
	}

	return &cometproto.CanonicalBlockID{
		Hash: bid.Hash,
		PartSetHeader: cometproto.CanonicalPartSetHeader{
			Total: bid.PartSetHeader.Total,
			Hash:  bid.PartSetHeader.Hash,
		},
	}
}

type PartSetHeader struct {
	Total uint32
	Hash  []byte
}

type Block struct {
	Height    int64
	Round     int64
	Step      int8
	BlockID   *BlockID
	POLRound  int64
	VoteExtension []byte
	Timestamp time.Time
}

func (block Block) HRSKey() HRSKey {
	return HRSKey{
		Height: block.Height,
		Round:  block.Round,
		Step:   block.Step,
	}
}

func (block Block) HRSTKey() HRSTKey {
	return HRSTKey{
		Height:    block.Height,
		Round:     block.Round,
		Step:      block.Step,
		Timestamp: block.Timestamp.UnixNano(),
	}
}

func (block Block) ToProto() *grpccosigner.Block {
	b := &grpccosigner.Block{
		Height:    block.Height,
		Round:     block.Round,
		Step:      int32(block.Step),
		POLRound:  int32(block.POLRound),
		VoteExtension: block.VoteExtension,
		Timestamp: block.Timestamp.UnixNano(),
	}

	if block.BlockID != nil {
		b.BlockID = &grpccosigner.BlockID{
			Hash:               block.BlockID.Hash,
			PartSetHeaderTotal: block.BlockID.PartSetHeader.Total,
			PartSetHeaderHash:  block.BlockID.PartSetHeader.Hash,
		}
	}

	return b
}

func BlockFromProto(block *grpccosigner.Block) Block {
	b := Block{
		Height:    block.Height,
		Round:     block.Round,
		Step:      int8(block.Step),
		POLRound:  int64(block.POLRound),
		VoteExtension: block.VoteExtension,
		Timestamp: time.Unix(0, block.Timestamp),
	}

	if block.BlockID != nil {
		b.BlockID = &BlockID{
			Hash: block.BlockID.Hash,
			PartSetHeader: PartSetHeader{
				Total: block.BlockID.PartSetHeaderTotal,
				Hash:  block.BlockID.PartSetHeaderHash,
			},
		}
	}

	return b
}

func (b Block) ToCanonicalVote(chainID string) *cometproto.CanonicalVote {
	return &cometproto.CanonicalVote{
		Type:      StepToType(b.Step),
		Height:    b.Height,
		Round:     b.Round,
		Timestamp: b.Timestamp,
		ChainID:   chainID,
		BlockID:   b.BlockID.ToCanonical(),
	}
}

func (b Block) ToCanonicalVoteNoTimestamp(chainID string) cometproto.CanonicalVoteNoTimestamp {
	return cometproto.CanonicalVoteNoTimestamp{
		Type:    StepToType(b.Step),
		Height:  b.Height,
		Round:   b.Round,
		BlockID: b.BlockID.ToCanonical(),
		ChainID: chainID,
	}
}

func (b Block) ToCanonicalVoteExtension(chainID string) cometproto.CanonicalVoteExtension {
	return cometproto.CanonicalVoteExtension{
		Extension: b.VoteExtension,
		Height:  b.Height,
		Round:   b.Round,
		ChainId:   chainID,
	}
}

func (b Block) ToCanonicalProposal(chainID string) *cometproto.CanonicalProposal {
	return &cometproto.CanonicalProposal{
		Type:      cometproto.ProposalType,
		Height:    b.Height,
		Round:     b.Round,
		POLRound:  int64(b.POLRound),
		BlockID:   b.BlockID.ToCanonical(),
		Timestamp: b.Timestamp,
		ChainID:   chainID,
	}
}
