package signer

import "github.com/strangelove-ventures/horcrux/signer/localthreshold"

// Interface for which is used by local  Signer
type ThresholdEd25519Signature interface {
	dealShares(req localthreshold.CosignerGetEphemeralSecretPartRequest) (localthreshold.HrsMetadata, error)

	getEphemeralSecretPart(req localthreshold.CosignerGetEphemeralSecretPartRequest) (CosignerEphemeralSecretPart, error)

	setEphemeralSecretPart(req CosignerSetEphemeralSecretPartRequest) error

	sign(req CosignerSignRequest) (CosignerSignResponse, error)
}
