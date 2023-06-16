package signer

const (
	SignerTypeSoftSign = "SoftSign"
	SignerTypeHSM      = "HSM"
)

// Interface for the local signer whether it's a soft sign or HSM
type ThresholdSigner interface {
	Type() string

	DealShares(req CosignerGetEphemeralSecretPartRequest) ([]CosignerMetadata, error)

	GetEphemeralSecretPart(req CosignerGetEphemeralSecretPartRequest, m *LastSignStateWrapper,
		pubKeys map[int]CosignerRSAPubKey) (CosignerEphemeralSecretPart, error)

	SetEphemeralSecretPart(req CosignerSetEphemeralSecretPartRequest, m *LastSignStateWrapper,
		pubKeys map[int]CosignerRSAPubKey) error

	Sign(req CosignerSignRequest, m *LastSignStateWrapper) (CosignerSignResponse, error)

	GetID() (int, error)

	// Stop performs any cleanup work, such as flushing state files to disk, then shut down.
	Stop()
}

// CosignerMetadata holds the share and the ephermeral secret public key
// Moved from Local cosigner to threshold_ed25519
type CosignerMetadata struct {
	Shares                   [][]byte
	EphemeralSecretPublicKey []byte
}
