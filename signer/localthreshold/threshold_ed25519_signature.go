package localthreshold

// Interface for which is used by local  Signer
type ThresholdEd25519Signature interface {
	dealShares(req CosignerGetEphemeralSecretPartRequest) (HrsMetadata, error)

	getEphemeralSecretPart(req CosignerGetEphemeralSecretPartRequest) (CosignerEphemeralSecretPart, error)

	setEphemeralSecretPart(req CosignerSetEphemeralSecretPartRequest) error

	sign(req CosignerSignRequest) (CosignerSignResponse, error)
}
