package types

import (
	"github.com/strangelove-ventures/horcrux/pkg/proto"
)

// HRSKey represents the key for the HRS metadata map.
// Height is the block height.
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
func HRSTKeyFromProto(hrs *proto.HRST) HRSTKey {
	return HRSTKey{
		Height:    hrs.GetHeight(),
		Round:     hrs.GetRound(),
		Step:      int8(hrs.GetStep()),
		Timestamp: hrs.GetTimestamp(),
	}
}

func (hrst HRSTKey) ToProto() *proto.HRST {
	return &proto.HRST{
		Height:    hrst.Height,
		Round:     hrst.Round,
		Step:      int32(hrst.Step),
		Timestamp: hrst.Timestamp,
	}
}
