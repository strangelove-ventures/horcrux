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

	height, round, step, err := UnpackHRS(signBytes)
	require.NoError(test, err)
	require.Equal(test, int64(1), height)
	require.Equal(test, int64(2), round)
	require.Equal(test, int8(2), step)
}

func TestUnpackHRSPrecommit(test *testing.T) {
	vote := tmproto.Vote{
		Height: 3,
		Round:  2,
		Type:   tmproto.PrecommitType,
	}

	signBytes := tm.VoteSignBytes("chain-id", &vote)

	height, round, step, err := UnpackHRS(signBytes)
	require.NoError(test, err)
	require.Equal(test, int64(3), height)
	require.Equal(test, int64(2), round)
	require.Equal(test, int8(3), step)
}

func TestUnpackHRSProposal(test *testing.T) {
	proposal := tmproto.Proposal{
		Height: 1,
		Round:  2,
		Type:   tmproto.ProposalType,
	}

	signBytes := tm.ProposalSignBytes("chain-id", &proposal)

	height, round, step, err := UnpackHRS(signBytes)
	require.NoError(test, err)
	require.Equal(test, int64(1), height)
	require.Equal(test, int64(2), round)
	require.Equal(test, int8(1), step)
}
