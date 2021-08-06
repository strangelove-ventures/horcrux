package signer

import "time"

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

type CosignerGetEphemeralSecretPartRequest struct {
	ID     int
	Height int64
	Round  int64
	Step   int8
}

type CosignerHasEphemeralSecretPartRequest struct {
	ID     int
	Height int64
	Round  int64
	Step   int8
}

type CosignerHasEphemeralSecretPartResponse struct {
	Exists                   bool
	EphemeralSecretPublicKey []byte
}

type CosignerGetEphemeralSecretPartResponse struct {
	SourceID                       int
	SourceEphemeralSecretPublicKey []byte
	EncryptedSharePart             []byte
	SourceSig                      []byte
}

type CosignerSetEphemeralSecretPartRequest struct {
	SourceID                       int
	SourceEphemeralSecretPublicKey []byte
	Height                         int64
	Round                          int64
	Step                           int8
	EncryptedSharePart             []byte
	SourceSig                      []byte
}

// Cosigner interface is a set of methods for an m-of-n threshold signature.
// This interface abstracts the underlying key storage and management
type Cosigner interface {
	// Get the ID of the cosigner
	// The ID is the shamir index: 1, 2, etc...
	GetID() int

	// Get the ephemeral secret part for an ephemeral share
	// The ephemeral secret part is encrypted for the receiver
	GetEphemeralSecretPart(req CosignerGetEphemeralSecretPartRequest) (CosignerGetEphemeralSecretPartResponse, error)

	// Store an ephemeral secret share part provided by another cosigner
	SetEphemeralSecretPart(req CosignerSetEphemeralSecretPartRequest) error

	// Query whether the cosigner has an ehpemeral secret part set
	HasEphemeralSecretPart(req CosignerHasEphemeralSecretPartRequest) (CosignerHasEphemeralSecretPartResponse, error)

	// Sign the requested bytes
	Sign(req CosignerSignRequest) (CosignerSignResponse, error)
}
