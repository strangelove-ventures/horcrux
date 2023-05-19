package signer

import (
	tsed25519 "gitlab.com/unit410/threshold-ed25519/pkg"
)

const (
	SignerTypeSoftSign = "SoftSign"
	SignerTypeHSM      = "HSM"
)

// Interface for the local signer whether it's a soft sign or HSM
type ThresholdSigner interface {
	Type() string

	DealShares(req CosignerGetEphemeralSecretPartRequest) (HrsMetadata, error)

	GetEphemeralSecretPart(req CosignerGetEphemeralSecretPartRequest, m *LastSignStateWrapper,
		pubKeys map[uint8]CosignerRSAPubKey) (CosignerEphemeralSecretPart, error)

	SetEphemeralSecretPart(req CosignerSetEphemeralSecretPartRequest, m *LastSignStateWrapper,
		pubKeys map[uint8]CosignerRSAPubKey) error

	Sign(req CosignerSignRequest, m *LastSignStateWrapper) (CosignerSignResponse, error)

	GetID() (uint8, error)

	// Stop performs any cleanup work, such as flushing state files to disk, then shut down.
	Stop()
}

// CosignerMetadata holds the share and the ephermeral secret public key
// Moved from Local cosigner to threshold_ed25519
type CosignerMetadata struct {
	Share                    []byte
	EphemeralSecretPublicKey []byte
}

// HrsMetadata holds the ephemeral nonces from cosigner peers
// for a given height, round, step.
type HrsMetadata struct {
	// need to be _total_ entries per player
	Secret      []byte
	DealtShares []tsed25519.Scalar
	Cosigners   []CosignerMetadata
}
