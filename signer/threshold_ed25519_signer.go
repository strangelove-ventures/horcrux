package signer

import (
	"crypto/rsa"
	"log"

	tsed25519 "gitlab.com/unit410/threshold-ed25519/pkg"
)

const (
	SignerTypeSoftSign = "SoftSign"
	SignerTypeHSM      = "HSM"
)

type SignerTypeConfig struct {
	CosignerKey CosignerKey
	RsaKey      rsa.PrivateKey
	Total       uint8
	Threshold   uint8
}

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

type ThresholdEd25519SignatureConfig interface {
	NewThresholdEd25519Signature() ThresholdEd25519Signature
}

// Initializes the signer depending on the type of signer type coded in the config.
// TODO: Fix so that also HSM can be called and add tbe embedding SignerConfig
func NewLocalSigner(signerType string, cfg SignerTypeConfig) ThresholdEd25519Signature {
	switch signerType {
	case SignerTypeHSM:
		// Placeholder for future HSM implementation.
		localsigner := NewLocalHSMSignThresholdEd25519SignatureConfig(cfg)
		return localsigner.NewThresholdEd25519Signature()
	default:
		// calling the function to initialize a Config struct for Softsign
		// panic("Need to be Softsign as its the only one implemented")
		log.Println("Default is Softsign. Softsign is the only SignerType implemented so far")
		localsigner := NewLocalSoftSignThresholdEd25519SignatureConfig(cfg)
		return localsigner.NewThresholdEd25519Signature()
	}
}
