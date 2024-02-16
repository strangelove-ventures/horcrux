package types

import (
	// "github.com/strangelove-ventures/horcrux/src/proto"
	"github.com/strangelove-ventures/horcrux/proto/strangelove/proto"
)

// HRS represents the HRS (Height, Round Step) metadata map.
type HRS struct {
	Height int64
	Round  int64
	Step   int8
}

// GreaterThan returns true if the HRS struct is greater than the other HRS struct.
func (hrs HRS) GreaterThan(other HRS) bool {
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

// LessThan returns true if the HRS is less than the other HRS.
func (hrs HRS) LessThan(other HRS) bool {
	return hrs != other && !hrs.GreaterThan(other)
}

// HRST represents the HRS metadata key with a timestamp.
type HRST struct {
	Height    int64
	Round     int64
	Step      int8
	Timestamp int64
}

// HRS returns the HRS portion of the HRSTKey.
func (hrst HRST) HRS() HRS {
	return HRS{
		Height: hrst.Height,
		Round:  hrst.Round,
		Step:   hrst.Step,
	}
}

// HRSTFromProto returns a HRSTKey from a proto.HRST.
func HRSTFromProto(hrst *proto.HRST) HRST {
	return HRST{
		Height:    hrst.GetHeight(),
		Round:     hrst.GetRound(),
		Step:      int8(hrst.GetStep()),
		Timestamp: hrst.GetTimestamp(),
	}
}

func (hrst HRST) ToProto() *proto.HRST {
	return &proto.HRST{
		Height:    hrst.Height,
		Round:     hrst.Round,
		Step:      int32(hrst.Step),
		Timestamp: hrst.Timestamp,
	}
}
