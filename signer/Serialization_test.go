package signer

import (
	"testing"

	"github.com/stretchr/testify/require"
	tmproto "github.com/tendermint/tendermint/proto/tendermint/types"
	tm "github.com/tendermint/tendermint/types"
)

func TestUnpackHRSPrevote(test *testing.T) {
	vote := tmproto.Vote{
		Height: 1,
		Round:  2,
		Type:   tmproto.PrevoteType,
	}

	signBytes := tm.VoteSignBytes("chain-id", &vote)

	hrs, err := UnpackHRS(signBytes)
	require.NoError(test, err)
	require.Equal(test, int64(1), hrs.Height)
	require.Equal(test, int64(2), hrs.Round)
	require.Equal(test, int8(2), hrs.Step)
}

func TestUnpackHRSPrecommit(test *testing.T) {
	vote := tmproto.Vote{
		Height: 3,
		Round:  2,
		Type:   tmproto.PrecommitType,
	}

	signBytes := tm.VoteSignBytes("chain-id", &vote)

	hrs, err := UnpackHRS(signBytes)
	require.NoError(test, err)
	require.Equal(test, int64(3), hrs.Height)
	require.Equal(test, int64(2), hrs.Round)
	require.Equal(test, int8(3), hrs.Step)
}

func TestUnpackHRSProposal(test *testing.T) {
	proposal := tmproto.Proposal{
		Height: 1,
		Round:  2,
		Type:   tmproto.ProposalType,
	}

	signBytes := tm.ProposalSignBytes("chain-id", &proposal)

	hrs, err := UnpackHRS(signBytes)
	require.NoError(test, err)
	require.Equal(test, int64(1), hrs.Height)
	require.Equal(test, int64(2), hrs.Round)
	require.Equal(test, int8(1), hrs.Step)
}
