package signer

import (
	tsed25519 "gitlab.com/polychainlabs/threshold-ed25519/pkg"
)

// Interface for the local signer whetever its a soft sign or hms
type ThresholdEd25519Signature interface {
	DealShares(req CosignerGetEphemeralSecretPartRequest) (HrsMetadata, error)

	GetEphemeralSecretPart(req CosignerGetEphemeralSecretPartRequest, m *LastSignStateStruct,
		peers map[int]CosignerPeer) (CosignerEphemeralSecretPart, error)

	SetEphemeralSecretPart(req CosignerSetEphemeralSecretPartRequest, m *LastSignStateStruct,
		peers map[int]CosignerPeer) error

	Sign(req CosignerSignRequest, m *LastSignStateStruct) (CosignerSignResponse, error)

	GetID() int
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

type ThresholdEd25519SignatureConfig interface {
	NewThresholdEd25519Signature() ThresholdEd25519Signature
}

// TODO: Fix so that also HSM can be called
func NewLocalSigner(signertype string, cfg LocalCosignerConfig) ThresholdEd25519Signature {
	switch signertype {
	case "SoftSign":
		localsigner := NewLocalSoftSignThresholdEd25519SignatureConfig(cfg)
		return localsigner.NewThresholdEd25519Signature()
	case "HSMsign":
		panic("Not Implemented")
		// localsigner := NewLocalHSMSignThresholdEd25519SignatureConfig(cfg)
		// return localsigner.NewThresholdEd25519Signature()
	default:
		panic("Need to be Softsign as its the only one implemented")
	}
}
