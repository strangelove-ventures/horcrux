package types

import (
	"errors"
	"fmt"
	"time"

	cometproto "github.com/strangelove-ventures/horcrux/v3/comet/proto/types"
	grpccosigner "github.com/strangelove-ventures/horcrux/v3/grpc/cosigner"
)

type BlockID struct {
	Hash          []byte        `json:"hash"`
	PartSetHeader PartSetHeader `json:"part_set_header"`
}

func (bid *BlockID) Equals(other *BlockID) bool {
	if bid == nil && other == nil {
		return true
	}

	if bid == nil || other == nil {
		return false
	}

	return string(bid.Hash) == string(other.Hash) &&
		bid.PartSetHeader.Total == other.PartSetHeader.Total &&
		string(bid.PartSetHeader.Hash) == string(other.PartSetHeader.Hash)
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
	Total uint32 `json:"total"`
	Hash  []byte `json:"hash"`
}

type Block struct {
	Height        int64
	Round         int64
	Step          int8
	BlockID       *BlockID
	POLRound      int64
	VoteExtension []byte
	Timestamp     time.Time
}

func (block Block) SignStateConsensus(signBytes, signature, voteExtensionSignature []byte) SignStateConsensus {
	return SignStateConsensus{
		Height:    block.Height,
		Round:     block.Round,
		Step:      block.Step,
		BlockID:   block.BlockID,
		POLRound:  block.POLRound,
		Timestamp: block.Timestamp.UnixNano(),

		SignBytes: signBytes,

		Signature:              signature,
		VoteExtensionSignature: voteExtensionSignature,
	}
}

func (block Block) EqualForSigning(newBlock Block) error {
	var errs error

	if block.Height != newBlock.Height {
		errs = errors.Join(errs, fmt.Errorf("conflicting data. heights do not match: %d != %d", block.Height, newBlock.Height))
	}

	if block.Round != newBlock.Round {
		errs = errors.Join(errs, fmt.Errorf("conflicting data. rounds do not match: %d != %d", block.Round, newBlock.Round))
	}

	if block.Step != newBlock.Step {
		errs = errors.Join(errs, fmt.Errorf("conflicting data. steps do not match: %d != %d", block.Step, newBlock.Step))
	}

	if block.POLRound != newBlock.POLRound {
		errs = errors.Join(errs, fmt.Errorf("conflicting data. polrounds do not match: %d != %d", block.POLRound, newBlock.POLRound))
	}

	if block.BlockID != nil && newBlock.BlockID == nil {
		errs = errors.Join(errs, fmt.Errorf("already signed non-nil blockID, but new blockID is nil"))
	} else if block.BlockID == nil && newBlock.BlockID != nil {
		errs = errors.Join(errs, fmt.Errorf("already signed nil blockID, but new blockID is non-nil"))
	} else if block.BlockID != nil && newBlock.BlockID != nil {
		if !block.BlockID.Equals(newBlock.BlockID) {
			errs = errors.Join(errs, fmt.Errorf("conflicting data. blockIDs do not match: %v != %v", block.BlockID, newBlock.BlockID))
		}
	}

	// Note Timestamp can change. It is okay to sign again if it does, so we
	// don't check or return an error here in the case of a timestamp mismatch.

	return errs
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
		Height:        block.Height,
		Round:         block.Round,
		Step:          int32(block.Step),
		POLRound:      int32(block.POLRound),
		VoteExtension: block.VoteExtension,
		Timestamp:     block.Timestamp.UnixNano(),
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
		Height:        block.Height,
		Round:         block.Round,
		Step:          int8(block.Step),
		POLRound:      int64(block.POLRound),
		VoteExtension: block.VoteExtension,
		Timestamp:     time.Unix(0, block.Timestamp),
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
		Height:    b.Height,
		Round:     b.Round,
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
