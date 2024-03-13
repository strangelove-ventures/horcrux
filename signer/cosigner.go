package signer

import (
	"context"
	"errors"
	"fmt"
	"time"

	cometcrypto "github.com/strangelove-ventures/horcrux/v3/comet/crypto"
	grpccosigner "github.com/strangelove-ventures/horcrux/v3/grpc/cosigner"
	"github.com/strangelove-ventures/horcrux/v3/types"
	"github.com/strangelove-ventures/horcrux/v3/comet/libs/protoio"

	"github.com/google/uuid"
)

// Cosigner interface is a set of methods for an m-of-n threshold signature.
// This interface abstracts the underlying key storage and management
type Cosigner interface {
	// Get the ID of the cosigner
	// The ID is the shamir index: 1, 2, etc...
	GetID() int

	// Get the P2P URL (GRPC and Raft)
	GetAddress() string

	// Get the combined public key
	GetPubKey(chainID string) (cometcrypto.PubKey, error)

	VerifySignature(chainID string, payload, signature []byte) bool

	// Get nonces for all cosigner shards
	GetNonces(ctx context.Context, uuids []uuid.UUID) (CosignerUUIDNoncesMultiple, error)

	// Sign the requested bytes
	SetNoncesAndSign(ctx context.Context, req CosignerSetNoncesAndSignRequest) (*CosignerSignResponse, error)
}

type Cosigners []Cosigner

func (cosigners Cosigners) GetByID(id int) Cosigner {
	for _, cosigner := range cosigners {
		if cosigner.GetID() == id {
			return cosigner
		}
	}
	return nil
}

// CosignerSignRequest is sent to a co-signer to obtain their signature for the SignBytes
// The SignBytes should be a serialized block
type CosignerSignRequest struct {
	ChainID string
	Block   types.Block
	UUID    uuid.UUID
	VoteExtUUID            uuid.UUID
}

type CosignerSignResponse struct {
	Timestamp                time.Time
	NoncePublic              []byte
	Signature                []byte
	VoteExtensionNoncePublic []byte
	VoteExtensionSignature   []byte
}

type CosignerNonce struct {
	SourceID      int
	DestinationID int
	PubKey        []byte
	Share         []byte
	Signature     []byte
}

func (secretPart *CosignerNonce) toProto() *grpccosigner.Nonce {
	return &grpccosigner.Nonce{
		SourceID:      int32(secretPart.SourceID),
		DestinationID: int32(secretPart.DestinationID),
		PubKey:        secretPart.PubKey,
		Share:         secretPart.Share,
		Signature:     secretPart.Signature,
	}
}

type CosignerNonces []CosignerNonce

func (secretParts CosignerNonces) toProto() (out []*grpccosigner.Nonce) {
	for _, secretPart := range secretParts {
		out = append(out, secretPart.toProto())
	}
	return
}

func CosignerNonceFromProto(secretPart *grpccosigner.Nonce) CosignerNonce {
	return CosignerNonce{
		SourceID:      int(secretPart.SourceID),
		DestinationID: int(secretPart.DestinationID),
		PubKey:        secretPart.PubKey,
		Share:         secretPart.Share,
		Signature:     secretPart.Signature,
	}
}

func CosignerNoncesFromProto(secretParts []*grpccosigner.Nonce) []CosignerNonce {
	out := make([]CosignerNonce, len(secretParts))
	for i, secretPart := range secretParts {
		out[i] = CosignerNonceFromProto(secretPart)
	}
	return out
}

type CosignerSignBlockRequest struct {
	ChainID string
	Block   *types.Block
}

type CosignerSignBlockResponse struct {
	Signature              []byte
	VoteExtensionSignature []byte
}
type CosignerUUIDNonces struct {
	UUID   uuid.UUID
	Nonces CosignerNonces
}

func (n *CosignerUUIDNonces) For(id int) *CosignerUUIDNonces {
	res := &CosignerUUIDNonces{UUID: n.UUID}
	for _, nonce := range n.Nonces {
		if nonce.DestinationID == id {
			res.Nonces = append(res.Nonces, nonce)
		}
	}
	return res
}

type CosignerUUIDNoncesMultiple []*CosignerUUIDNonces

func (n CosignerUUIDNoncesMultiple) toProto() []*grpccosigner.UUIDNonce {
	out := make([]*grpccosigner.UUIDNonce, len(n))
	for i, nonces := range n {
		out[i] = &grpccosigner.UUIDNonce{
			Uuid:   nonces.UUID[:],
			Nonces: nonces.Nonces.toProto(),
		}
	}
	return out
}

type CosignerSetNoncesAndSignRequest struct {
	ChainID string

	Nonces    *CosignerUUIDNonces
	VoteExtensionNonces    *CosignerUUIDNonces

	Block    types.Block
}
