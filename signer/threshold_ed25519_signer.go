package signer

import (
	tsed25519 "gitlab.com/unit410/threshold-ed25519/pkg"
)

const (
	SignerTypeSoftSign = "SoftSign"
	SignerTypeHSM      = "HSM"
)

// Interface for the local signer whetever its a soft sign or hms
type ThresholdEd25519Signature interface {
	DealShares(req CosignerGetEphemeralSecretPartRequest) (HrsMetadata, error)

	GetEphemeralSecretPart(req CosignerGetEphemeralSecretPartRequest, m *LastSignStateStruct,
		peers map[int]CosignerPeer) (CosignerEphemeralSecretPart, error)

	SetEphemeralSecretPart(req CosignerSetEphemeralSecretPartRequest, m *LastSignStateStruct,
		peers map[int]CosignerPeer) error

	Sign(req CosignerSignRequest, m *LastSignStateStruct) (CosignerSignResponse, error)

	GetID() (int, error)
}

// PeerMetadata holds the share and the ephermeral secret public key
// Moved from Local cosigner to threshold_ed25519
type PeerMetadata struct {
	Share                    []byte
	EphemeralSecretPublicKey []byte
}

// Moved from Local cosigner to threshold_ed25519
type HrsMetadata struct {
	// need to be _total_ entries per player
	Secret      []byte
	DealtShares []tsed25519.Scalar
	Peers       []PeerMetadata
}
