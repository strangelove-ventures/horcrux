package signer

import (
	"time"

	proto "github.com/strangelove-ventures/horcrux/signer/proto"
)

type HRSKey struct {
	Height int64
	Round  int64
	Step   int8
}

func HRSKeyFromProto(hrs *proto.HRS) HRSKey {
	return HRSKey{
		Height: hrs.GetHeight(),
		Round:  hrs.GetRound(),
		Step:   int8(hrs.GetStep()),
	}
}

func (hrsKey HRSKey) toProto() *proto.HRS {
	return &proto.HRS{
		Height: hrsKey.Height,
		Round:  hrsKey.Round,
		Step:   int32(hrsKey.Step),
	}
}

// CosignerSignRequest is sent to a co-signer to obtain their signature for the SignBytes
// The SignBytes should be a serialized block
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
	HRS              HRSKey
	SignBytes        []byte
}

// Cosigner interface is a set of methods for an m-of-n threshold signature.
// This interface abstracts the underlying key storage and management
type Cosigner interface {
	// Get the ID of the cosigner
	// The ID is the shamir index: 1, 2, etc...
	GetID() int

	// Get the P2P URL (GRPC and Raft)
	GetAddress() string

	// Get ephemeral secret part for all peers
	GetEphemeralSecretParts(req HRSKey) (*CosignerEphemeralSecretPartsResponse, error)

	// Sign the requested bytes
	SetEphemeralSecretPartsAndSign(req CosignerSetEphemeralSecretPartsAndSignRequest) (*CosignerSignResponse, error)
}
