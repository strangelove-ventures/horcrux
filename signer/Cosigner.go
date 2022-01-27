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

type CosignerEphemeralSecretPart struct {
	SourceID                       int
	DestinationID                  int
	SourceEphemeralSecretPublicKey []byte
	EncryptedSharePart             []byte
	SourceSig                      []byte
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
	Block   *block
}

type CosignerSignBlockResponse struct {
	Signature []byte
}

type CosignerEmitEphemeralSecretReceiptRequest struct {
	HRS           HRSKey
	SourceID      int
	DestinationID int
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

	// Get the RPC URL
	GetAddress() string

	// Get the raft host - hostname:port
	GetRaftAddress() string

	// Get ephemeral secret part for all peers
	GetEphemeralSecretParts(req HRSKey) (*CosignerEphemeralSecretPartsResponse, error)

	// Sign the requested bytes
	SetEphemeralSecretPartsAndSign(req CosignerSetEphemeralSecretPartsAndSignRequest) (*CosignerSignResponse, error)

	// Request that the cosigner manage the threshold signing process for this block
	// Will throw error if cosigner is not the leader
	SignBlock(req CosignerSignBlockRequest) (CosignerSignBlockResponse, error)
}
