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

type HRSTKey struct {
	Height    int64
	Round     int64
	Step      int8
	Timestamp int64
}

func HRSTKeyFromProto(hrs *proto.HRST) HRSTKey {
	return HRSTKey{
		Height:    hrs.GetHeight(),
		Round:     hrs.GetRound(),
		Step:      int8(hrs.GetStep()),
		Timestamp: hrs.GetTimestamp(),
	}
}

func (hrst HRSTKey) toProto() *proto.HRST {
	return &proto.HRST{
		Height:    hrst.Height,
		Round:     hrst.Round,
		Step:      int32(hrst.Step),
		Timestamp: hrst.Timestamp,
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
	// Get the ID of the cosigner
	// The ID is the shamir index: 1, 2, etc...
	GetID() int

	// Get the P2P URL (GRPC and Raft)
	GetAddress() string

	// Get ephemeral secret part for all peers
	GetEphemeralSecretParts(hrst HRSTKey) (*CosignerEphemeralSecretPartsResponse, error)

	// Sign the requested bytes
	SetEphemeralSecretPartsAndSign(req CosignerSetEphemeralSecretPartsAndSignRequest) (*CosignerSignResponse, error)
}
