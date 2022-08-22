package signer

import (
	"crypto/rsa"
	"sync"
	"time"
)

type CosignerPeer struct {
	ID        int
	PublicKey rsa.PublicKey
}

type CosignerGetEphemeralSecretPartRequest struct {
	ID        int
	Height    int64
	Round     int64
	Step      int8
	Timestamp time.Time
}

type LastSignStateStruct struct {
	// signing is thread safe - lastSignStateMutex is used for putting locks so only one goroutine can r/w to the function
	LastSignStateMutex sync.Mutex

	// lastSignState stores the last sign state for a share we have fully signed
	// incremented whenever we are asked to sign a share
	LastSignState *SignState
}

type LocalCosignerConfig struct {
	CosignerKey CosignerKey
	SignState   *SignState
	RsaKey      rsa.PrivateKey
	Peers       []CosignerPeer
	Address     string
	Total       uint8
	Threshold   uint8
}

// LocalCosigner responds to sign requests using their share key
// LocalCosigner signing is thread safe
// LocalCosigner "embedd" the threshold signer.
// The cosigner maintains a watermark to avoid double-signing
// TODO: Clarify what you mean with cosinger here, do you mean Local Cosigner?
type LocalCosigner struct {
	LastSignStateStruct *LastSignStateStruct
	address             string
	Peers               map[int]CosignerPeer
	localsigner         ThresholdEd25519Signature
}

// Initiatise a Local Cosigner
func NewLocalCosigner(cfg LocalCosignerConfig, localsigner ThresholdEd25519Signature) *LocalCosigner {

	LastSignStateStruct := LastSignStateStruct{
		LastSignStateMutex: sync.Mutex{},
		LastSignState:      cfg.SignState,
	}

	cosigner := &LocalCosigner{
		LastSignStateStruct: &LastSignStateStruct,
		// total:               cfg.Total,
		address: cfg.Address,

		localsigner: localsigner,
		Peers:       make(map[int]CosignerPeer),
	}

	for _, peer := range cfg.Peers {
		cosigner.Peers[peer.ID] = peer
	}

	return cosigner
}

func (cosigner *LocalCosigner) SaveLastSignedState(signState SignStateConsensus) error {
	return cosigner.LastSignStateStruct.LastSignState.Save(signState, &cosigner.LastSignStateStruct.LastSignStateMutex)
}

// GetID returns the id of the cosigner, via the localsigner getter
// Implements the Cosigner interface from Cosigner.go
func (cosigner *LocalCosigner) GetID() int {
	id, _ := cosigner.localsigner.GetID()
	return id
}

// GetAddress returns the GRPC URL of the cosigner
// Implements the Cosigner interface from Cosigner.go
func (cosigner *LocalCosigner) GetAddress() string {
	return cosigner.address
}

// GetEphemeralSecretParts
// // Implements the Cosigner interface from Cosigner.go
func (cosigner *LocalCosigner) GetEphemeralSecretParts(
	hrst HRSTKey) (*CosignerEphemeralSecretPartsResponse, error) {
	res := &CosignerEphemeralSecretPartsResponse{
		EncryptedSecrets: make([]CosignerEphemeralSecretPart, 0, len(cosigner.Peers)-1),
	}
	for _, peer := range cosigner.Peers {
		if peer.ID == cosigner.GetID() {
			continue
		}
		secretPart, err := cosigner.localsigner.GetEphemeralSecretPart(CosignerGetEphemeralSecretPartRequest{
			ID:        peer.ID,
			Height:    hrst.Height,
			Round:     hrst.Round,
			Step:      hrst.Step,
			Timestamp: time.Unix(0, hrst.Timestamp),
		}, cosigner.LastSignStateStruct,
			cosigner.Peers)

		if err != nil {
			return nil, err
		}

		res.EncryptedSecrets = append(res.EncryptedSecrets, secretPart)
	}
	return res, nil
}

// SetEphemeralSecretPartsAndSign
// // Implements the Cosigner interface from Cosigner.go
func (cosigner *LocalCosigner) SetEphemeralSecretPartsAndSign(
	req CosignerSetEphemeralSecretPartsAndSignRequest) (*CosignerSignResponse, error) {
	for _, secretPart := range req.EncryptedSecrets {
		err := cosigner.localsigner.SetEphemeralSecretPart(CosignerSetEphemeralSecretPartRequest{
			SourceID:                       secretPart.SourceID,
			SourceEphemeralSecretPublicKey: secretPart.SourceEphemeralSecretPublicKey,
			EncryptedSharePart:             secretPart.EncryptedSharePart,
			SourceSig:                      secretPart.SourceSig,
			Height:                         req.HRST.Height,
			Round:                          req.HRST.Round,
			Step:                           req.HRST.Step,
			Timestamp:                      time.Unix(0, req.HRST.Timestamp),
		}, cosigner.LastSignStateStruct, cosigner.Peers)
		if err != nil {
			return nil, err
		}
	}

	res, err := cosigner.localsigner.Sign(CosignerSignRequest{req.SignBytes}, cosigner.LastSignStateStruct)
	return &res, err
}
