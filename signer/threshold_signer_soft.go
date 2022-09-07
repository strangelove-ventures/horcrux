package signer

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"errors"
	"fmt"

	tmCryptoEd25519 "github.com/tendermint/tendermint/crypto/ed25519"
	tmJson "github.com/tendermint/tendermint/libs/json"
	"gitlab.com/unit410/edwards25519"
	tsed25519 "gitlab.com/unit410/threshold-ed25519/pkg"
)

// ThresholdSignerSoft implements the interface and signs the message for each local signer.
// ThresholdSignerSoft is the implementation of a soft sign signer at the local level.
type ThresholdSignerSoft struct {
	PubKeyBytes []byte
	Key         CosignerKey
	// Total signers
	Total     uint8
	Threshold uint8
	// Height, Round, Step, Timestamp --> metadata
	HrsMeta map[HRSTKey]HrsMetadata
}

// NewThresholdSignerSoft constructs a ThresholdSigner
// that signs using the local key share file.
func NewThresholdSignerSoft(
	key CosignerKey,
	threshold, total uint8,
) ThresholdSigner {
	softSigner := &ThresholdSignerSoft{
		Key:       key,
		HrsMeta:   make(map[HRSTKey]HrsMetadata),
		Total:     total,
		Threshold: threshold,
	}

	// cache the public key bytes for signing operations
	switch ed25519Key := softSigner.Key.PubKey.(type) {
	case tmCryptoEd25519.PubKey:
		softSigner.PubKeyBytes = make([]byte, len(ed25519Key))
		copy(softSigner.PubKeyBytes, ed25519Key[:])
	default:
		panic("Not an ed25519 public key")
	}
	return softSigner
}

// Implements ThresholdSigner
func (softSigner *ThresholdSignerSoft) Type() string {
	return "soft"
}

// Implements ThresholdSigner
func (softSigner *ThresholdSignerSoft) GetID() (int, error) {
	return softSigner.Key.ID, nil
}

// Implements ThresholdSigner
func (softSigner *ThresholdSignerSoft) Sign(
	req CosignerSignRequest, m *LastSignStateStruct) (CosignerSignResponse, error) {
	m.LastSignStateMutex.Lock()
	defer m.LastSignStateMutex.Unlock()

	res := CosignerSignResponse{}
	lss := m.LastSignState

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

	meta, ok := softSigner.HrsMeta[hrst]
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
		req.SignBytes, softSigner.Key.ShareKey, ephemeralShare, softSigner.PubKeyBytes, ephemeralPublic)

	m.LastSignState.EphemeralPublic = ephemeralPublic
	err = m.LastSignState.Save(SignStateConsensus{
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

	for existingKey := range softSigner.HrsMeta {
		// delete any HRS lower than our signed level
		// we will not be providing parts for any lower HRS
		if existingKey.Less(hrst) {
			delete(softSigner.HrsMeta, existingKey)
		}
	}

	res.EphemeralPublic = ephemeralPublic
	res.Signature = sig
	return res, nil
}

// Implements ThresholdSigner
func (softSigner *ThresholdSignerSoft) DealShares(
	req CosignerGetEphemeralSecretPartRequest) (HrsMetadata, error) {
	hrsKey := HRSTKey{
		Height:    req.Height,
		Round:     req.Round,
		Step:      req.Step,
		Timestamp: req.Timestamp.UnixNano(),
	}

	meta, ok := softSigner.HrsMeta[hrsKey]

	if ok {
		return meta, nil
	}

	secret := make([]byte, 32)
	if _, err := rand.Read(secret); err != nil {
		return HrsMetadata{}, err
	}

	meta = HrsMetadata{
		Secret: secret,
		Peers:  make([]PeerMetadata, softSigner.Total),
	}

	// split this secret with shamirs
	// !! dealt shares need to be saved because dealing produces different shares each time!
	meta.DealtShares = tsed25519.DealShares(meta.Secret, softSigner.Threshold, softSigner.Total)

	softSigner.HrsMeta[hrsKey] = meta

	return meta, nil
}

// Get the ephemeral secret part for an ephemeral share
// The ephemeral secret part is encrypted for the receiver
// Implements ThresholdSigner
func (softSigner *ThresholdSignerSoft) GetEphemeralSecretPart(
	req CosignerGetEphemeralSecretPartRequest, m *LastSignStateStruct, peers map[int]CosignerPeer) (
	CosignerEphemeralSecretPart, error) {

	res := CosignerEphemeralSecretPart{}

	// protects the meta map
	m.LastSignStateMutex.Lock()
	defer m.LastSignStateMutex.Unlock()

	hrst := HRSTKey{
		Height:    req.Height,
		Round:     req.Round,
		Step:      req.Step,
		Timestamp: req.Timestamp.UnixNano(),
	}

	meta, ok := softSigner.HrsMeta[hrst]
	// generate metadata placeholder
	if !ok {
		newMeta, err := softSigner.DealShares(CosignerGetEphemeralSecretPartRequest{
			Height:    req.Height,
			Round:     req.Round,
			Step:      req.Step,
			Timestamp: req.Timestamp,
		})

		if err != nil {
			return res, err
		}

		meta = newMeta
		softSigner.HrsMeta[hrst] = meta
	}

	ourEphPublicKey := tsed25519.ScalarMultiplyBase(meta.Secret)

	// set our values
	meta.Peers[softSigner.Key.ID-1].Share = meta.DealtShares[softSigner.Key.ID-1]
	meta.Peers[softSigner.Key.ID-1].EphemeralSecretPublicKey = ourEphPublicKey

	// grab the peer info for the ID being requested
	peer, ok := peers[req.ID]
	if !ok {
		return res, errors.New("unknown peer ID")
	}

	sharePart := meta.DealtShares[req.ID-1]

	// use RSA public to encrypt user's share part
	encrypted, err := rsa.EncryptOAEP(sha256.New(), rand.Reader, &peer.PublicKey, sharePart, nil)
	if err != nil {
		return res, err
	}

	res.SourceID = softSigner.Key.ID
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
		signature, err := rsa.SignPSS(rand.Reader, &softSigner.Key.RSAKey, crypto.SHA256, digest[:], nil)
		if err != nil {
			return res, err
		}

		res.SourceSig = signature
	}

	res.DestinationID = req.ID

	return res, nil
}

// Store an ephemeral secret share part provided by another cosigner (signer)
// Implements ThresholdSigner
func (softSigner *ThresholdSignerSoft) SetEphemeralSecretPart(
	req CosignerSetEphemeralSecretPartRequest, m *LastSignStateStruct, peers map[int]CosignerPeer) error {

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
		peer, ok := peers[req.SourceID]

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
	m.LastSignStateMutex.Lock()
	defer m.LastSignStateMutex.Unlock()

	hrst := HRSTKey{
		Height:    req.Height,
		Round:     req.Round,
		Step:      req.Step,
		Timestamp: req.Timestamp.UnixNano(),
	}

	meta, ok := softSigner.HrsMeta[hrst]
	// generate metadata placeholder
	if !ok {
		newMeta, err := softSigner.DealShares(CosignerGetEphemeralSecretPartRequest{
			Height: req.Height,
			Round:  req.Round,
			Step:   req.Step,
		})

		if err != nil {
			return err
		}

		meta = newMeta
		softSigner.HrsMeta[hrst] = meta
	}

	// decrypt share
	sharePart, err := rsa.DecryptOAEP(sha256.New(), rand.Reader, &softSigner.Key.RSAKey, req.EncryptedSharePart, nil)
	if err != nil {
		return err
	}

	// set slot
	meta.Peers[req.SourceID-1].Share = sharePart
	meta.Peers[req.SourceID-1].EphemeralSecretPublicKey = req.SourceEphemeralSecretPublicKey
	return nil
}
