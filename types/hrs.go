package types

import (
	"errors"

	"github.com/strangelove-ventures/horcrux/v3/comet/libs/protoio"
	cometproto "github.com/strangelove-ventures/horcrux/v3/comet/proto/types"
	grpccosigner "github.com/strangelove-ventures/horcrux/v3/grpc/cosigner"
)

// HRSKey represents the key for the HRS metadata map.
type HRSKey struct {
	Height int64
	Round  int64
	Step   int8
}

// GreaterThan returns true if the HRSKey is greater than the other HRSKey.
func (hrs HRSKey) GreaterThan(other HRSKey) bool {
	if hrs.Height > other.Height {
		return true
	}
	if hrs.Height < other.Height {
		return false
	}
	if hrs.Round > other.Round {
		return true
	}
	if hrs.Round < other.Round {
		return false
	}
	return hrs.Step > other.Step
}

// LessThan returns true if the HRSKey is less than the other HRSKey.
func (hrs HRSKey) LessThan(other HRSKey) bool {
	return hrs != other && !hrs.GreaterThan(other)
}

// HRSTKey represents the HRS metadata key with a timestamp.
type HRSTKey struct {
	Height    int64
	Round     int64
	Step      int8
	Timestamp int64
}

// HRSKey returns the HRSKey portion of the HRSTKey.
func (hrst HRSTKey) HRSKey() HRSKey {
	return HRSKey{
		Height: hrst.Height,
		Round:  hrst.Round,
		Step:   hrst.Step,
	}
}

// HRSTKeyFromProto returns a HRSTKey from a proto.HRST.
func HRSTKeyFromProto(hrs *grpccosigner.HRST) HRSTKey {
	return HRSTKey{
		Height:    hrs.GetHeight(),
		Round:     hrs.GetRound(),
		Step:      int8(hrs.GetStep()),
		Timestamp: hrs.GetTimestamp(),
	}
}

func (hrst HRSTKey) ToProto() *grpccosigner.HRST {
	return &grpccosigner.HRST{
		Height:    hrst.Height,
		Round:     hrst.Round,
		Step:      int32(hrst.Step),
		Timestamp: hrst.Timestamp,
	}
}

// UnpackHRS deserializes sign bytes and gets the height, round, and step
func UnpackHRST(signBytes []byte) (HRSTKey, error) {
	{
		var proposal cometproto.CanonicalProposal
		if err := protoio.UnmarshalDelimited(signBytes, &proposal); err == nil {
			return HRSTKey{proposal.Height, proposal.Round, StepPropose, proposal.Timestamp.UnixNano()}, nil
		}
	}

	{
		var vote cometproto.CanonicalVote
		if err := protoio.UnmarshalDelimited(signBytes, &vote); err == nil {
			return HRSTKey{vote.Height, vote.Round, CanonicalVoteToStep(&vote), vote.Timestamp.UnixNano()}, nil
		}
	}

	return HRSTKey{0, 0, 0, 0}, errors.New("could not UnpackHRS from sign bytes")
}
