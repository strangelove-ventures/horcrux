package ed25519

import (
	"fmt"

	"github.com/strangelove-ventures/horcrux/v3/comet/libs/protoio"
	cometproto "github.com/strangelove-ventures/horcrux/v3/comet/proto/types"
	"github.com/strangelove-ventures/horcrux/v3/types"
)

func SignBytes(chainID string, block types.Block) ([]byte, []byte, error) {
	t := types.StepToType(block.Step)

	switch t {
	case cometproto.PrevoteType, cometproto.PrecommitType:
		var extBytes []byte
		if block.Step == types.StepPrecommit && !block.BlockID.IsZero() {
			extBytes = VoteExtensionSignBytes(chainID, block)
		}
		return VoteSignBytes(chainID, block), extBytes, nil
	case cometproto.ProposalType:
		return ProposalSignBytes(chainID, block), nil, nil
	default:
		return nil, nil, fmt.Errorf("unknown step type: %v", t)
	}
}

func VoteSignBytes(chainID string, vote types.Block) []byte {
	pb := vote.ToCanonicalVote(chainID)
	bz, err := protoio.MarshalDelimited(pb)
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
