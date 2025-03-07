package bn254

import (
	"fmt"
	"math/big"

	"github.com/consensys/gnark-crypto/ecc/bn254/fr/mimc"
	"github.com/strangelove-ventures/horcrux/v3/comet/libs/protoio"
	cometproto "github.com/strangelove-ventures/horcrux/v3/comet/proto/types"
	"github.com/strangelove-ventures/horcrux/v3/types"
)

func SignBytes(chainID string, block types.Block) ([]byte, []byte, error) {
	t := types.StepToType(block.Step)

	switch t {
	case cometproto.PrecommitType, cometproto.PrevoteType:
		var extBytes []byte
		if block.Step == types.StepPrecommit && !block.BlockID.IsZero() {
			extBytes = VoteExtensionSignBytes(chainID, block)
		}

		// For union v0.20+
		return VoteSignBytes(chainID, block), extBytes, nil
	case cometproto.ProposalType:
		return ProposalSignBytes(chainID, block), nil, nil
	default:
		return nil, nil, fmt.Errorf("unknown step type: %v", t)
	}
}

func VoteSignBytesPre(chainID string, vote types.Block) []byte {
	pb := vote.ToCanonicalVoteNoTimestamp(chainID)
	bz, err := protoio.MarshalDelimited(&pb)
	if err != nil {
		panic(err)
	}

	return bz
}

func ProposalSignBytes(chainID string, proposal types.Block) []byte {
	pb := proposal.ToCanonicalProposal(chainID)
	bz, err := protoio.MarshalDelimited(pb)
	if err != nil {
		panic(err)
	}

	return bz
}

// VoteExtensionSignBytes returns the proto-encoding of the canonicalized vote
// extension for signing. Panics if the marshaling fails.
//
// Similar to VoteSignBytes, the encoded Protobuf message is varint
// length-prefixed for backwards-compatibility with the Amino encoding.
func VoteExtensionSignBytes(chainID string, vote types.Block) []byte {
	pb := vote.ToCanonicalVoteExtension(chainID)
	bz, err := protoio.MarshalDelimited(&pb)
	if err != nil {
		panic(err)
	}

	return bz
}

// VoteSignBytes returns the proto-encoding of the canonicalized Vote, for
// signing. Panics if the marshaling fails.
//
// The encoded Protobuf message is varint length-prefixed (using MarshalDelimited)
// for backwards-compatibility with the Amino encoding, due to e.g. hardware
// devices that rely on this encoding.
//
// See CanonicalizeVote
func VoteSignBytes(chainID string, vote types.Block) []byte {
	padBytes := func(b []byte) []byte {
		var padded [32]byte
		if b == nil {
			return padded[:]
		}
		return big.NewInt(0).SetBytes(b).FillBytes(padded[:])
	}

	mimc := mimc.NewMiMC()
	var padded [32]byte
	writeI64 := func(x int64) {
		big.NewInt(x).FillBytes(padded[:])
		_, err := mimc.Write(padded[:])
		if err != nil {
			panic(err)
		}
	}
	writeU32 := func(x uint32) {
		big.NewInt(0).SetUint64(uint64(x)).FillBytes(padded[:])
		_, err := mimc.Write(padded[:])
		if err != nil {
			panic(err)
		}
	}
	writeMiMCHash := func(b []byte) {
		_, err := mimc.Write(b)
		if err != nil {
			panic(err)
		}
	}
	writeHash := func(b []byte) {
		if len(b) == 0 {
			b = make([]byte, 32)
		}
		head, tail := b[0], b[1:]
		writeMiMCHash(padBytes([]byte{head}))
		writeMiMCHash(padBytes(tail))
	}
	writeBytes := func(b []byte) {
		if len(b) > 31 {
			panic("impossible: bytes must fit in F_r")
		}
		_, err := mimc.Write(padBytes(b))
		if err != nil {
			panic(err)
		}
	}

	writeI64(int64(types.StepToType(vote.Step)))
	writeI64(vote.Height)
	writeI64(vote.Round)
	if vote.BlockID == nil {
		writeMiMCHash([]byte{})
		writeI64(0)
		writeMiMCHash([]byte{})
	} else {
		writeMiMCHash(vote.BlockID.Hash)
		writeU32(vote.BlockID.PartSetHeader.Total)
		if vote.BlockID.PartSetHeader.Hash == nil {
			writeMiMCHash([]byte{})
		} else {
			writeHash(vote.BlockID.PartSetHeader.Hash)
		}
	}
	writeBytes([]byte(chainID))

	return mimc.Sum(nil)
}
