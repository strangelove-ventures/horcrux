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
	// Signing is thread safe - lastSignStateMutex is used for putting locks so only one goroutine can r/w to the function
	LastSignStateMutex sync.Mutex

	// lastSignState stores the last sign state for a share we have fully signed
	// incremented whenever we are asked to sign a share
	LastSignState *SignState
}

// LocalCosigner responds to sign requests using their share key
// LocalCosigner "embeds" the Threshold signer.
// LocalCosigner maintains a watermark to avoid double-signing via the embedded LastSignStateStruct.
// LocalCosigner signing is thread safe by embedding *LastSignStateStruct which contains LastSignStateMutex sync.Mutex.
type LocalCosigner struct {
	LastSignStateStruct *LastSignStateStruct
	address             string
	Peers               map[int]CosignerPeer
	thresholdSigner     ThresholdSigner
}

// Initialize a Local Cosigner
func NewLocalCosigner(
	address string,
	peers []CosignerPeer,
	signState *SignState,
	thresholdSigner ThresholdSigner,
) *LocalCosigner {

	LastSignStateStruct := LastSignStateStruct{
		// Mutex  doesnt need to be initialized mean we can skip: LastSignStateMutex: sync.Mutex{},
		LastSignState: signState,
	}

	cosigner := &LocalCosigner{
		LastSignStateStruct: &LastSignStateStruct,
		address:             address,
		thresholdSigner:     thresholdSigner,
		Peers:               make(map[int]CosignerPeer),
	}

	for _, peer := range peers {
		cosigner.Peers[peer.ID] = peer
	}

	return cosigner
}

func (cosigner *LocalCosigner) SaveLastSignedState(signState SignStateConsensus) error {
	return cosigner.LastSignStateStruct.LastSignState.Save(
		signState, &cosigner.LastSignStateStruct.LastSignStateMutex, true)
}

// GetID returns the id of the cosigner, via the thresholdSigner getter
// Implements the Cosigner interface from Cosigner.go
func (cosigner *LocalCosigner) GetID() int {
	id, _ := cosigner.thresholdSigner.GetID()
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
		secretPart, err := cosigner.thresholdSigner.GetEphemeralSecretPart(CosignerGetEphemeralSecretPartRequest{
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
// Implements the Cosigner interface from Cosigner.go
func (cosigner *LocalCosigner) SetEphemeralSecretPartsAndSign(
	req CosignerSetEphemeralSecretPartsAndSignRequest) (*CosignerSignResponse, error) {
	for _, secretPart := range req.EncryptedSecrets {
		err := cosigner.thresholdSigner.SetEphemeralSecretPart(CosignerSetEphemeralSecretPartRequest{
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

	res, err := cosigner.thresholdSigner.Sign(CosignerSignRequest{req.SignBytes}, cosigner.LastSignStateStruct)
	return &res, err
}
