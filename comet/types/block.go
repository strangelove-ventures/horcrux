package types

import (
	"crypto/sha256"
	"errors"
	fmt "fmt"

	"github.com/strangelove-ventures/horcrux/v3/comet/crypto"
	tmproto "github.com/strangelove-ventures/horcrux/v3/comet/proto/types"
)

const tmhashSize = sha256.Size

// Address is hex bytes.
type Address = crypto.Address

// BlockID
type BlockID struct {
	Hash          []byte        `json:"hash"`
	PartSetHeader PartSetHeader `json:"parts"`
}

// ValidateBasic performs basic validation.
func (blockID BlockID) ValidateBasic() error {
	// Hash can be empty in case of POLBlockID in Proposal.
	if err := ValidateHash(blockID.Hash); err != nil {
		return fmt.Errorf("wrong Hash")
	}
	if err := blockID.PartSetHeader.ValidateBasic(); err != nil {
		return fmt.Errorf("wrong PartSetHeader: %v", err)
	}
	return nil
}

// IsZero returns true if this is the BlockID of a nil block.
func (blockID BlockID) IsZero() bool {
	return len(blockID.Hash) == 0 &&
		blockID.PartSetHeader.IsZero()
}

// ValidateHash returns an error if the hash is not empty, but its
// size != tmhash.Size.
func ValidateHash(h []byte) error {
	if len(h) > 0 && len(h) != tmhashSize {
		return fmt.Errorf("expected size to be %d bytes, got %d bytes",
			tmhashSize,
			len(h),
		)
	}
	return nil
}

// FromProto sets a protobuf BlockID to the given pointer.
// It returns an error if the block id is invalid.
func BlockIDFromProto(bID *tmproto.BlockID) (*BlockID, error) {
	if bID == nil {
		return nil, errors.New("nil BlockID")
	}

	blockID := new(BlockID)
	ph, err := PartSetHeaderFromProto(&bID.PartSetHeader)
	if err != nil {
		return nil, err
	}

	blockID.PartSetHeader = *ph
	blockID.Hash = bID.Hash

	return blockID, blockID.ValidateBasic()
}
