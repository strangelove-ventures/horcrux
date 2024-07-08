package types

import (
	"bytes"
	"encoding/hex"
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

// IsZero returns true if this is the BlockID of a nil block.
func (bid *BlockID) IsZero() bool {
	return len(bid.Hash) == 0 && bid.PartSetHeader.IsZero()
}

func (bid *BlockID) Equals(other *BlockID) bool {
	if bid == nil && other == nil {
		return true
	}

	if bid == nil || other == nil {
		return false
	}

	return bytes.Equal(bid.Hash, other.Hash) &&
		bid.PartSetHeader.Total == other.PartSetHeader.Total &&
		bytes.Equal(bid.PartSetHeader.Hash, other.PartSetHeader.Hash)
}

func (bid *BlockID) ToCanonical() *cometproto.CanonicalBlockID {
	if bid == nil {
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

func (psh PartSetHeader) IsZero() bool {
	return psh.Total == 0 && len(psh.Hash) == 0
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

func (b Block) SignStateConsensus(signBytes, signature, voteExtensionSignature []byte) SignStateConsensus {
	return SignStateConsensus{
		Height:    b.Height,
		Round:     b.Round,
		Step:      b.Step,
		BlockID:   b.BlockID,
		POLRound:  b.POLRound,
		Timestamp: b.Timestamp.UnixNano(),

		SignBytes: signBytes,

		Signature:              signature,
		VoteExtensionSignature: voteExtensionSignature,
	}
}

func (b Block) EqualForSigning(newBlock Block) error {
	var errs error

	if b.Height != newBlock.Height {
		errs = errors.Join(errs, fmt.Errorf(
			"conflicting data. heights do not match: %d != %d", b.Height, newBlock.Height,
		))
	}

	if b.Round != newBlock.Round {
		errs = errors.Join(errs, fmt.Errorf(
			"conflicting data. rounds do not match: %d != %d", b.Round, newBlock.Round,
		))
	}

	if b.Step != newBlock.Step {
		errs = errors.Join(errs, fmt.Errorf(
			"conflicting data. steps do not match: %d != %d", b.Step, newBlock.Step,
		))
	}

	if b.POLRound != newBlock.POLRound {
		errs = errors.Join(errs, fmt.Errorf(
			"conflicting data. polrounds do not match: %d != %d", b.POLRound, newBlock.POLRound,
		))
	}

	switch {
	case b.BlockID != nil && newBlock.BlockID == nil:
		errs = errors.Join(errs, fmt.Errorf("already signed non-nil blockID, but new blockID is nil"))
	case b.BlockID == nil && newBlock.BlockID != nil:
		errs = errors.Join(errs, fmt.Errorf("already signed nil blockID, but new blockID is non-nil"))
	case b.BlockID != nil && newBlock.BlockID != nil:
		if !b.BlockID.Equals(newBlock.BlockID) {
			errs = errors.Join(errs, fmt.Errorf(
				"conflicting data. blockIDs do not match: %s != %s",
				hex.EncodeToString(newBlock.BlockID.Hash),
				hex.EncodeToString(newBlock.BlockID.Hash),
			))
		}
	}

	// Note Timestamp can change. It is okay to sign again if it does, so we
	// don't check or return an error here in the case of a timestamp mismatch.

	return errs
}

func (b Block) HRSKey() HRSKey {
	return HRSKey{
		Height: b.Height,
		Round:  b.Round,
		Step:   b.Step,
	}
}

func (b Block) HRSTKey() HRSTKey {
	return HRSTKey{
		Height:    b.Height,
		Round:     b.Round,
		Step:      b.Step,
		Timestamp: b.Timestamp.UnixNano(),
	}
}

func (b Block) ToProto() *grpccosigner.Block {
	block := &grpccosigner.Block{
		Height:        b.Height,
		Round:         b.Round,
		Step:          int32(b.Step),
		POLRound:      int32(b.POLRound),
		VoteExtension: b.VoteExtension,
		Timestamp:     b.Timestamp.UnixNano(),
	}

	if b.BlockID != nil {
		block.BlockID = &grpccosigner.BlockID{
			Hash:               b.BlockID.Hash,
			PartSetHeaderTotal: b.BlockID.PartSetHeader.Total,
			PartSetHeaderHash:  b.BlockID.PartSetHeader.Hash,
		}
	}

	return block
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
		POLRound:  b.POLRound,
		BlockID:   b.BlockID.ToCanonical(),
		Timestamp: b.Timestamp,
		ChainID:   chainID,
	}
}
