package signer

import (
	"testing"

	tmproto "github.com/cometbft/cometbft/proto/tendermint/types"
	tm "github.com/cometbft/cometbft/types"
	"github.com/stretchr/testify/require"
)

func TestUnpackHRSPrevote(t *testing.T) {
	vote := tmproto.Vote{
		Height: 1,
		Round:  2,
		Type:   tmproto.PrevoteType,
	}

	signBytes := tm.VoteSignBytes("chain-id", &vote)

	hrs, err := UnpackHRST(signBytes)
	require.NoError(t, err)
	require.Equal(t, int64(1), hrs.Height)
	require.Equal(t, int64(2), hrs.Round)
	require.Equal(t, int8(2), hrs.Step)
}

func TestUnpackHRSPrecommit(t *testing.T) {
	vote := tmproto.Vote{
		Height: 3,
		Round:  2,
		Type:   tmproto.PrecommitType,
	}

	signBytes := tm.VoteSignBytes("chain-id", &vote)

	hrs, err := UnpackHRST(signBytes)
	require.NoError(t, err)
	require.Equal(t, int64(3), hrs.Height)
	require.Equal(t, int64(2), hrs.Round)
	require.Equal(t, int8(3), hrs.Step)
}

func TestUnpackHRSProposal(t *testing.T) {
	proposal := tmproto.Proposal{
		Height: 1,
		Round:  2,
		Type:   tmproto.ProposalType,
	}

	signBytes := tm.ProposalSignBytes("chain-id", &proposal)

	hrs, err := UnpackHRST(signBytes)
	require.NoError(t, err)
	require.Equal(t, int64(1), hrs.Height)
	require.Equal(t, int64(2), hrs.Round)
	require.Equal(t, int8(1), hrs.Step)
}
