package signer

import (
	"time"

	proto "github.com/strangelove-ventures/horcrux/signer/proto"
)

// HRSKey Height Round Step Key to keep track of ...?
type HRSKey struct {
	Height int64
	Round  int64
	Step   int8
}

// HRSTKey Height Round Step Time to keep track of ....?
type HRSTKey struct {
	Height    int64
	Round     int64
	Step      int8
	Timestamp int64
}

// HRSTKeyFromProto Gets TODO: Explain more
func HRSTKeyFromProto(hrs *proto.HRST) HRSTKey {
	return HRSTKey{
		Height:    hrs.GetHeight(),
		Round:     hrs.GetRound(),
		Step:      int8(hrs.GetStep()),
		Timestamp: hrs.GetTimestamp(),
	}
}

// toProto is a HRSTKey method that returns proto.HRST
func (hrst HRSTKey) toProto() *proto.HRST {
	return &proto.HRST{
		Height:    hrst.Height,
		Round:     hrst.Round,
		Step:      int32(hrst.Step),
		Timestamp: hrst.Timestamp,
	}
}

// Less is a HRSTKey method that return true if we are less than the other key
func (hrst *HRSTKey) Less(other HRSTKey) bool {
	if hrst.Height < other.Height {
		return true
	}

	if hrst.Height > other.Height {
		return false
	}

	// height is equal, check round

	if hrst.Round < other.Round {
		return true
	}

	if hrst.Round > other.Round {
		return false
	}

	// round is equal, check step

	if hrst.Step < other.Step {
		return true
	}

	// HRS is greater or equal
	return false
}

// CosignerSignRequest is sent to a co-signer to obtain their signature for the SignBytes
// SignBytes should be a serialized block
type CosignerSignRequest struct {
	SignBytes []byte
}

type CosignerSignResponse struct {
	EphemeralPublic []byte
	Timestamp       time.Time
	Signature       []byte
}

type CosignerEphemeralSecretPart struct {
	SourceID                       int
	DestinationID                  int
	SourceEphemeralSecretPublicKey []byte
	EncryptedSharePart             []byte
	SourceSig                      []byte
}

func (secretPart *CosignerEphemeralSecretPart) toProto() *proto.EphemeralSecretPart {
	return &proto.EphemeralSecretPart{
		SourceID:                       int32(secretPart.SourceID),
		DestinationID:                  int32(secretPart.DestinationID),
		SourceEphemeralSecretPublicKey: secretPart.SourceEphemeralSecretPublicKey,
		EncryptedSharePart:             secretPart.EncryptedSharePart,
		SourceSig:                      secretPart.SourceSig,
	}
}

type CosignerEphemeralSecretParts []CosignerEphemeralSecretPart

func (secretParts CosignerEphemeralSecretParts) toProto() (out []*proto.EphemeralSecretPart) {
	for _, secretPart := range secretParts {
		out = append(out, secretPart.toProto())
	}
	return
}

func CosignerEphemeralSecretPartFromProto(secretPart *proto.EphemeralSecretPart) CosignerEphemeralSecretPart {
	return CosignerEphemeralSecretPart{
		SourceID:                       int(secretPart.SourceID),
		DestinationID:                  int(secretPart.DestinationID),
		SourceEphemeralSecretPublicKey: secretPart.SourceEphemeralSecretPublicKey,
		EncryptedSharePart:             secretPart.EncryptedSharePart,
		SourceSig:                      secretPart.SourceSig,
	}
}

func CosignerEphemeralSecretPartsFromProto(
	secretParts []*proto.EphemeralSecretPart) (out []CosignerEphemeralSecretPart) {
	for _, secretPart := range secretParts {
		out = append(out, CosignerEphemeralSecretPartFromProto(secretPart))
	}
	return
}

type CosignerSetEphemeralSecretPartRequest struct {
	SourceID                       int
	SourceEphemeralSecretPublicKey []byte
	EncryptedSharePart             []byte
	SourceSig                      []byte
	Height                         int64
	Round                          int64
	Step                           int8
	Timestamp                      time.Time
}

type CosignerSignBlockRequest struct {
	ChainID string
	Block   *Block
}

type CosignerSignBlockResponse struct {
	Signature []byte
}

type CosignerEphemeralSecretPartsResponse struct {
	EncryptedSecrets []CosignerEphemeralSecretPart
}

type CosignerSetEphemeralSecretPartsAndSignRequest struct {
	EncryptedSecrets []CosignerEphemeralSecretPart
	HRST             HRSTKey
	SignBytes        []byte
}

// Cosigner interface is a set of methods for an m-of-n threshold signature.
// This interface abstracts the underlying key storage and management
type Cosigner interface {
	// GetID gets the ID of the cosigner
	// The ID is the shamir index: 1, 2, etc...
	GetID() int

	// GetAddress gets the P2P URL (GRPC and Raft)
	GetAddress() string

	// GetEphemeralSecretParts gets ephemeral secret part for all peers
	GetEphemeralSecretParts(hrst HRSTKey) (*CosignerEphemeralSecretPartsResponse, error)

	// SetEphemeralSecretPartsAndSign sign the requested bytes
	SetEphemeralSecretPartsAndSign(req CosignerSetEphemeralSecretPartsAndSignRequest) (*CosignerSignResponse, error)
}
