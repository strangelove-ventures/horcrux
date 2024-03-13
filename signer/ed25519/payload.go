package ed25519

import (
	"fmt"

	"github.com/strangelove-ventures/horcrux/v3/comet/libs/protoio"
	cometproto "github.com/strangelove-ventures/horcrux/v3/comet/proto/types"
	"github.com/strangelove-ventures/horcrux/v3/types"
)

func SignBytes(chainID string, block types.Block) ([]byte, error) {
	t := types.StepToType(block.Step)

	switch t {
	case cometproto.PrecommitType, cometproto.PrevoteType:
		return protoio.MarshalDelimited(block.ToCanonicalVote(chainID))
	case cometproto.ProposalType:
		return protoio.MarshalDelimited(block.ToCanonicalProposal(chainID))
	default:
		return nil, fmt.Errorf("unknown step type: %v", t)
	}
}
