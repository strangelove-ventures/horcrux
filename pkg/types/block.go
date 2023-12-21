package types

import (
	"time"

	"github.com/strangelove-ventures/horcrux/signer/proto"
)

type Block struct {
	Height    int64
	Round     int64
	Step      int8
	SignBytes []byte
	Timestamp time.Time
}

func (block Block) HRSKey() HRSKey {
	return HRSKey{
		Height: block.Height,
		Round:  block.Round,
		Step:   block.Step,
	}
}

func (block Block) HRSTKey() HRSTKey {
	return HRSTKey{
		Height:    block.Height,
		Round:     block.Round,
		Step:      block.Step,
		Timestamp: block.Timestamp.UnixNano(),
	}
}

func (block Block) ToProto() *proto.Block {
	return &proto.Block{
		Height:    block.Height,
		Round:     block.Round,
		Step:      int32(block.Step),
		SignBytes: block.SignBytes,
		Timestamp: block.Timestamp.UnixNano(),
	}
}

func BlockFromProto(block *proto.Block) Block {
	return Block{
		Height:    block.Height,
		Round:     block.Round,
		Step:      int8(block.Step),
		SignBytes: block.SignBytes,
		Timestamp: time.Unix(0, block.Timestamp),
	}
}
