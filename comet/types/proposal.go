package types

import (
	"github.com/strangelove-ventures/horcrux/v3/comet/libs/protoio"
	cmtproto "github.com/strangelove-ventures/horcrux/v3/comet/proto/types"
)

// ProposalSignBytes returns the proto-encoding of the canonicalized Proposal,
// for signing. Panics if the marshaling fails.
//
// The encoded Protobuf message is varint length-prefixed (using MarshalDelimited)
// for backwards-compatibility with the Amino encoding, due to e.g. hardware
// devices that rely on this encoding.
//
// See CanonicalizeProposal
func ProposalSignBytes(chainID string, p *cmtproto.Proposal) []byte {
	pb := CanonicalizeProposal(chainID, p)
	bz, err := protoio.MarshalDelimited(&pb)
	if err != nil {
		panic(err)
	}

	return bz
}
