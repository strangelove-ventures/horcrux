package signer

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"errors"
	"fmt"
	"sync"

	tmJson "github.com/tendermint/tendermint/libs/json"
	"gitlab.com/polychainlabs/edwards25519"
	tsed25519 "gitlab.com/polychainlabs/threshold-ed25519/pkg"
)

// Interface for which is used by local  Signer
type ThresholdEd25519Signature interface {
	DealShares(req CosignerGetEphemeralSecretPartRequest) (HrsMetadata, error)

	GetEphemeralSecretPart(req CosignerGetEphemeralSecretPartRequest) (CosignerEphemeralSecretPart, error)

	SetEphemeralSecretPart(req CosignerSetEphemeralSecretPartRequest) error

	Sign(req CosignerSignRequest) (CosignerSignResponse, error)
}

// LocalSoftsignThresholdEd25519Signature
type LocalSoftSignThresholdEd25519Signature struct {
	//UnimplementedThresholdEd25519Signature // embedding unimplemented ThresholdEd25519Signature
	PubKeyBytes []byte
	Key         CosignerKey
	RsaKey      rsa.PrivateKey
	Total       uint8
	Threshold   uint8

	// stores the last sign state for a share we have fully signed
	// incremented whenever we are asked to sign a share
	LastSignState *SignState

	// signing is thread safe
	LastSignStateMutex sync.Mutex

	// Height, Round, Step -> metadata
	HrsMeta map[HRSTKey]HrsMetadata
	Peers   map[int]CosignerPeer
}

func (cosigner *LocalSoftSignThresholdEd25519Signature) Sign(req CosignerSignRequest) (CosignerSignResponse, error) {
	cosigner.LastSignStateMutex.Lock()
	defer cosigner.LastSignStateMutex.Unlock()

	res := CosignerSignResponse{}
	lss := cosigner.LastSignState

	hrst, err := UnpackHRST(req.SignBytes)
	if err != nil {
		return res, err
	}

	sameHRS, err := lss.CheckHRS(hrst)
	if err != nil {
		return res, err
	}

	// If the HRS is the same the sign bytes may still differ by timestamp
	// It is ok to re-sign a different timestamp if that is the only difference in the sign bytes
	if sameHRS {
		if bytes.Equal(req.SignBytes, lss.SignBytes) {
			res.EphemeralPublic = lss.EphemeralPublic
			res.Signature = lss.Signature
			return res, nil
		} else if err := lss.OnlyDifferByTimestamp(req.SignBytes); err != nil {
			return res, err
		}

		// same HRS, and only differ by timestamp - ok to sign again
	}

	meta, ok := cosigner.HrsMeta[hrst]
	if !ok {
		return res, errors.New("no metadata at HRS")
	}

	shareParts := make([]tsed25519.Scalar, 0)
	publicKeys := make([]tsed25519.Element, 0)

	// calculate secret and public keys
	for _, peer := range meta.Peers {
		if len(peer.Share) == 0 {
			continue
		}
		shareParts = append(shareParts, peer.Share)
		publicKeys = append(publicKeys, peer.EphemeralSecretPublicKey)
	}

	ephemeralShare := tsed25519.AddScalars(shareParts)
	ephemeralPublic := tsed25519.AddElements(publicKeys)

	// check bounds for ephemeral share to avoid passing out of bounds valids to SignWithShare
	{
		if len(ephemeralShare) != 32 {
			return res, errors.New("ephemeral share is out of bounds")
		}

		var scalarBytes [32]byte
		copy(scalarBytes[:], ephemeralShare)
		if !edwards25519.ScMinimal(&scalarBytes) {
			return res, errors.New("ephemeral share is out of bounds")
		}
	}

	sig := tsed25519.SignWithShare(
		req.SignBytes, cosigner.Key.ShareKey, ephemeralShare, cosigner.PubKeyBytes, ephemeralPublic)

	cosigner.LastSignState.EphemeralPublic = ephemeralPublic
	err = cosigner.LastSignState.Save(SignStateConsensus{
		Height:    hrst.Height,
		Round:     hrst.Round,
		Step:      hrst.Step,
		Signature: sig,
		SignBytes: req.SignBytes,
	}, nil)

	if err != nil {
		if _, isSameHRSError := err.(*SameHRSError); !isSameHRSError {
			return res, err
		}
	}

	for existingKey := range cosigner.HrsMeta {
		// delete any HRS lower than our signed level
		// we will not be providing parts for any lower HRS
		if existingKey.Less(hrst) {
			delete(cosigner.HrsMeta, existingKey)
		}
	}

	res.EphemeralPublic = ephemeralPublic
	res.Signature = sig
	return res, nil
}

// Implements ThresholdEd25519Signature interface
func (cosigner *LocalSoftSignThresholdEd25519Signature) DealShares(req CosignerGetEphemeralSecretPartRequest) (HrsMetadata, error) {
	hrsKey := HRSTKey{
		Height:    req.Height,
		Round:     req.Round,
		Step:      req.Step,
		Timestamp: req.Timestamp.UnixNano(),
	}

	meta, ok := cosigner.HrsMeta[hrsKey]

	if ok {
		return meta, nil
	}

	secret := make([]byte, 32)
	if _, err := rand.Read(secret); err != nil {
		return HrsMetadata{}, err
	}

	meta = HrsMetadata{
		Secret: secret,
		Peers:  make([]PeerMetadata, cosigner.Total),
	}

	// split this secret with shamirs
	// !! dealt shares need to be saved because dealing produces different shares each time!
	meta.DealtShares = tsed25519.DealShares(meta.Secret, cosigner.Threshold, cosigner.Total)

	cosigner.HrsMeta[hrsKey] = meta

	return meta, nil
}

// Get the ephemeral secret part for an ephemeral share
// The ephemeral secret part is encrypted for the receiver
// Implements ThresholdEd25519Signature interface
func (cosigner *LocalSoftSignThresholdEd25519Signature) GetEphemeralSecretPart(
	req CosignerGetEphemeralSecretPartRequest) (CosignerEphemeralSecretPart, error) {
	res := CosignerEphemeralSecretPart{}

	// protects the meta map
	cosigner.LastSignStateMutex.Lock()
	defer cosigner.LastSignStateMutex.Unlock()

	hrst := HRSTKey{
		Height:    req.Height,
		Round:     req.Round,
		Step:      req.Step,
		Timestamp: req.Timestamp.UnixNano(),
	}

	meta, ok := cosigner.HrsMeta[hrst]
	// generate metadata placeholder
	if !ok {
		newMeta, err := cosigner.DealShares(CosignerGetEphemeralSecretPartRequest{
			Height:    req.Height,
			Round:     req.Round,
			Step:      req.Step,
			Timestamp: req.Timestamp,
		})

		if err != nil {
			return res, err
		}

		meta = newMeta
		cosigner.HrsMeta[hrst] = meta
	}

	ourEphPublicKey := tsed25519.ScalarMultiplyBase(meta.Secret)

	// set our values
	meta.Peers[cosigner.Key.ID-1].Share = meta.DealtShares[cosigner.Key.ID-1]
	meta.Peers[cosigner.Key.ID-1].EphemeralSecretPublicKey = ourEphPublicKey

	// grab the peer info for the ID being requested
	peer, ok := cosigner.Peers[req.ID]
	if !ok {
		return res, errors.New("unknown peer ID")
	}

	sharePart := meta.DealtShares[req.ID-1]

	// use RSA public to encrypt user's share part
	encrypted, err := rsa.EncryptOAEP(sha256.New(), rand.Reader, &peer.PublicKey, sharePart, nil)
	if err != nil {
		return res, err
	}

	res.SourceID = cosigner.Key.ID
	res.SourceEphemeralSecretPublicKey = ourEphPublicKey
	res.EncryptedSharePart = encrypted

	// sign the response payload with our private key
	// cosigners can verify the signature to confirm sender validity
	{
		jsonBytes, err := tmJson.Marshal(res)

		if err != nil {
			return res, err
		}

		digest := sha256.Sum256(jsonBytes)
		signature, err := rsa.SignPSS(rand.Reader, &cosigner.RsaKey, crypto.SHA256, digest[:], nil)
		if err != nil {
			return res, err
		}

		res.SourceSig = signature
	}

	res.DestinationID = req.ID

	return res, nil
}

// Store an ephemeral secret share part provided by another cosigner
// Implements ThresholdEd25519Signature interface
func (cosigner *LocalSoftSignThresholdEd25519Signature) SetEphemeralSecretPart(req CosignerSetEphemeralSecretPartRequest) error {

	// Verify the source signature
	{
		if req.SourceSig == nil {
			return errors.New("SourceSig field is required")
		}

		digestMsg := CosignerEphemeralSecretPart{}
		digestMsg.SourceID = req.SourceID
		digestMsg.SourceEphemeralSecretPublicKey = req.SourceEphemeralSecretPublicKey
		digestMsg.EncryptedSharePart = req.EncryptedSharePart

		digestBytes, err := tmJson.Marshal(digestMsg)
		if err != nil {
			return err
		}

		digest := sha256.Sum256(digestBytes)
		peer, ok := cosigner.Peers[req.SourceID]

		if !ok {
			return fmt.Errorf("unknown cosigner: %d", req.SourceID)
		}

		peerPub := peer.PublicKey
		err = rsa.VerifyPSS(&peerPub, crypto.SHA256, digest[:], req.SourceSig, nil)
		if err != nil {
			return err
		}
	}

	// protects the meta map
	cosigner.LastSignStateMutex.Lock()
	defer cosigner.LastSignStateMutex.Unlock()

	hrst := HRSTKey{
		Height:    req.Height,
		Round:     req.Round,
		Step:      req.Step,
		Timestamp: req.Timestamp.UnixNano(),
	}

	meta, ok := cosigner.HrsMeta[hrst]
	// generate metadata placeholder
	if !ok {
		newMeta, err := cosigner.DealShares(CosignerGetEphemeralSecretPartRequest{
			Height: req.Height,
			Round:  req.Round,
			Step:   req.Step,
		})

		if err != nil {
			return err
		}

		meta = newMeta
		cosigner.HrsMeta[hrst] = meta
	}

	// decrypt share
	sharePart, err := rsa.DecryptOAEP(sha256.New(), rand.Reader, &cosigner.RsaKey, req.EncryptedSharePart, nil)
	if err != nil {
		return err
	}

	// set slot
	meta.Peers[req.SourceID-1].Share = sharePart
	meta.Peers[req.SourceID-1].EphemeralSecretPublicKey = req.SourceEphemeralSecretPublicKey
	return nil
}

//Local LocalHSMsignThresholdEd25519Signature

type LocalHSMsignThresholdEd25519Signature struct {
	// panic("Not Implemented") //TODO:
	//UnimplementedThresholdEd25519Signature // embedding UnimplementedCosignerGRPCServer

}

/*

// UnimplementedThresholdEd25519Signature must be embedded to have forward compatible implementations.
type UnimplementedThresholdEd25519Signature struct {
}

func (UnimplementedThresholdEd25519Signature) dealShares(req CosignerGetEphemeralSecretPartRequest) (HrsMetadata, error) {
	return HrsMetadata{}, errors.New("method dealShares not implemented")
}
func (UnimplementedThresholdEd25519Signature) setEphemeralSecretPart(req CosignerSetEphemeralSecretPartRequest) error {
	return errors.New("method setEphemeralSecretPart not implemented")
}
func (UnimplementedThresholdEd25519Signature) getEphemeralSecretPart(req CosignerGetEphemeralSecretPartRequest) (CosignerEphemeralSecretPart, error) {
	return CosignerEphemeralSecretPart{}, errors.New("method getEphemeralSecretPart")
}
func (UnimplementedThresholdEd25519Signature) sign(req CosignerSignRequest) (CosignerSignResponse, error) {
	return CosignerSignResponse{}, errors.New("method sign not implemented")
}

func (cosigner LocalHSMsignThresholdEd25519Signature) dealShares(req CosignerGetEphemeralSecretPartRequest) (HrsMetadata, error) {
	panic("Not Implemented") //TODO:
	return HrsMetadata{}, errors.New("method dealShares not implemented")
}
func (cosigner LocalHSMsignThresholdEd25519Signature) setEphemeralSecretPart(req CosignerSetEphemeralSecretPartRequest) error {
	panic("Not Implemented") //TODO:
	return errors.New("method setEphemeralSecretPart not implemented")
}
func (cosigner LocalHSMsignThresholdEd25519Signature) getEphemeralSecretPart(req CosignerGetEphemeralSecretPartRequest) (CosignerEphemeralSecretPart, error) {
	panic("Not Implemented") //TODO:
	return CosignerEphemeralSecretPart{}, errors.New("method getEphemeralSecretPart")
}
func (cosigner LocalHSMsignThresholdEd25519Signature) sign(req CosignerSignRequest) (CosignerSignResponse, error) {
	panic("Not Implemented") //TODO:
	return CosignerSignResponse{}, errors.New("method sign not implemented")
}
*/
