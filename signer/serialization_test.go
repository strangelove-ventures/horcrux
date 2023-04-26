package signer

import (
	"testing"

	cbftproto "github.com/cometbft/cometbft/proto/tendermint/types"
	cbft "github.com/cometbft/cometbft/types"
	"github.com/stretchr/testify/require"
)

func TestUnpackHRSPrevote(t *testing.T) {
	vote := cbftproto.Vote{
		Height: 1,
		Round:  2,
		Type:   cbftproto.PrevoteType,
	}

	signBytes := cbft.VoteSignBytes("chain-id", &vote)

	hrs, err := UnpackHRST(signBytes)
	require.NoError(t, err)
	require.Equal(t, int64(1), hrs.Height)
	require.Equal(t, int64(2), hrs.Round)
	require.Equal(t, int8(2), hrs.Step)
}

func TestUnpackHRSPrecommit(t *testing.T) {
	vote := cbftproto.Vote{
		Height: 3,
		Round:  2,
		Type:   cbftproto.PrecommitType,
	}

	signBytes := cbft.VoteSignBytes("chain-id", &vote)

	hrs, err := UnpackHRST(signBytes)
	require.NoError(t, err)
	require.Equal(t, int64(3), hrs.Height)
	require.Equal(t, int64(2), hrs.Round)
	require.Equal(t, int8(3), hrs.Step)
}

func TestUnpackHRSProposal(t *testing.T) {
	proposal := cbftproto.Proposal{
		Height: 1,
		Round:  2,
		Type:   cbftproto.ProposalType,
	}

	signBytes := cbft.ProposalSignBytes("chain-id", &proposal)

	hrs, err := UnpackHRST(signBytes)
	require.NoError(t, err)
	require.Equal(t, int64(1), hrs.Height)
	require.Equal(t, int64(2), hrs.Round)
	require.Equal(t, int8(1), hrs.Step)
}
