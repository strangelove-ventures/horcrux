package signer

import (
	tsed25519 "gitlab.com/polychainlabs/threshold-ed25519/pkg"
)

// Interface for the local signer whetever its a soft sign or hms
type ThresholdEd25519Signature interface {
	DealShares(req CosignerGetEphemeralSecretPartRequest) (HrsMetadata, error)

	GetEphemeralSecretPart(req CosignerGetEphemeralSecretPartRequest) (CosignerEphemeralSecretPart, error)

	SetEphemeralSecretPart(req CosignerSetEphemeralSecretPartRequest) error

	Sign(req CosignerSignRequest) (CosignerSignResponse, LastSignStateStruct, error)
}

// PeerMetadata holds the share and the ephermeral secret public key
// Moved from Local Cosigner to threshold_ed25519
type PeerMetadata struct {
	Share                    []byte
	EphemeralSecretPublicKey []byte
}

// Moved from Local Cosigner to threshold_ed25519
type HrsMetadata struct {
	// need to be _total_ entries per player
	Secret      []byte
	DealtShares []tsed25519.Scalar
	Peers       []PeerMetadata
}
