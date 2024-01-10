package signer

import (
	"context"
	"errors"
	"fmt"
	"time"

	cometcrypto "github.com/cometbft/cometbft/crypto"
	"github.com/cometbft/cometbft/libs/protoio"
	cometproto "github.com/cometbft/cometbft/proto/tendermint/types"
	"github.com/google/uuid"
	"github.com/strangelove-ventures/horcrux/v3/signer/proto"
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
	ChainID                string
	SignBytes              []byte
	UUID                   uuid.UUID
	VoteExtensionSignBytes []byte
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

func (secretPart *CosignerNonce) toProto() *proto.Nonce {
	return &proto.Nonce{
		SourceID:      int32(secretPart.SourceID),
		DestinationID: int32(secretPart.DestinationID),
		PubKey:        secretPart.PubKey,
		Share:         secretPart.Share,
		Signature:     secretPart.Signature,
	}
}

type CosignerNonces []CosignerNonce

func (secretParts CosignerNonces) toProto() (out []*proto.Nonce) {
	for _, secretPart := range secretParts {
		out = append(out, secretPart.toProto())
	}
	return
}

func CosignerNonceFromProto(secretPart *proto.Nonce) CosignerNonce {
	return CosignerNonce{
		SourceID:      int(secretPart.SourceID),
		DestinationID: int(secretPart.DestinationID),
		PubKey:        secretPart.PubKey,
		Share:         secretPart.Share,
		Signature:     secretPart.Signature,
	}
}

func CosignerNoncesFromProto(secretParts []*proto.Nonce) []CosignerNonce {
	out := make([]CosignerNonce, len(secretParts))
	for i, secretPart := range secretParts {
		out[i] = CosignerNonceFromProto(secretPart)
	}
	return out
}

type CosignerSignBlockRequest struct {
	ChainID string
	Block   *Block
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

func (n CosignerUUIDNoncesMultiple) toProto() []*proto.UUIDNonce {
	out := make([]*proto.UUIDNonce, len(n))
	for i, nonces := range n {
		out[i] = &proto.UUIDNonce{
			Uuid:   nonces.UUID[:],
			Nonces: nonces.Nonces.toProto(),
		}
	}
	return out
}

type CosignerSetNoncesAndSignRequest struct {
	ChainID string
	HRST    HRSTKey

	Nonces    *CosignerUUIDNonces
	SignBytes []byte

	VoteExtensionNonces    *CosignerUUIDNonces
	VoteExtensionSignBytes []byte
}

func verifySignPayload(chainID string, signBytes, voteExtensionSignBytes []byte) (HRSTKey, bool, error) {
	var vote cometproto.CanonicalVote
	voteErr := protoio.UnmarshalDelimited(signBytes, &vote)
	if voteErr == nil && (vote.Type == cometproto.PrevoteType || vote.Type == cometproto.PrecommitType) {
		hrstKey := HRSTKey{
			Height:    vote.Height,
			Round:     vote.Round,
			Step:      CanonicalVoteToStep(&vote),
			Timestamp: vote.Timestamp.UnixNano(),
		}

		if hrstKey.Step == stepPrecommit && len(voteExtensionSignBytes) > 0 && vote.BlockID != nil {
			var voteExt cometproto.CanonicalVoteExtension
			if err := protoio.UnmarshalDelimited(voteExtensionSignBytes, &voteExt); err != nil {
				return hrstKey, false, fmt.Errorf("failed to unmarshal vote extension: %w", err)
			}
			if voteExt.ChainId != chainID {
				return hrstKey, false, fmt.Errorf("vote extension chain ID %s does not match chain ID %s", voteExt.ChainId, chainID)
			}
			if voteExt.Height != hrstKey.Height {
				return hrstKey, false,
					fmt.Errorf("vote extension height %d does not match block height %d", voteExt.Height, hrstKey.Height)
			}
			if voteExt.Round != hrstKey.Round {
				return hrstKey, false,
					fmt.Errorf("vote extension round %d does not match block round %d", voteExt.Round, hrstKey.Round)
			}
			return hrstKey, true, nil
		}

		return hrstKey, false, nil
	}

	var proposal cometproto.CanonicalProposal
	proposalErr := protoio.UnmarshalDelimited(signBytes, &proposal)
	if proposalErr == nil {
		return HRSTKey{
			Height:    proposal.Height,
			Round:     proposal.Round,
			Step:      stepPropose,
			Timestamp: proposal.Timestamp.UnixNano(),
		}, false, nil
	}

	return HRSTKey{}, false,
		fmt.Errorf("failed to unmarshal sign bytes into vote or proposal: %w", errors.Join(voteErr, proposalErr))
}
