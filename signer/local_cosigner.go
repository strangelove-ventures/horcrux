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
	"time"

	tmcryptoed25519 "github.com/tendermint/tendermint/crypto/ed25519"
	tmjson "github.com/tendermint/tendermint/libs/json"
	"gitlab.com/unit410/edwards25519"
	tsed25519 "gitlab.com/unit410/threshold-ed25519/pkg"
)

type LastSignStateWrapper struct {
	// Signing is thread safe - lastSignStateMutex is used for putting locks so only one goroutine can r/w to the function
	lastSignStateMutex sync.Mutex

	// lastSignState stores the last sign state for a share we have fully signed
	// incremented whenever we are asked to sign a share
	LastSignState *SignState
}

type ChainState struct {
	// Signing is thread safe - lastSignStateMutex is used for putting locks so only one goroutine can r/w to the function
	lastSignStateMutex *sync.Mutex

	// lastSignState stores the last sign state for a share we have fully signed
	// incremented whenever we are asked to sign a share
	LastSignState *SignState

	// Height, Round, Step -> metadata
	hrsMeta map[HRSTKey]HrsMetadata
}

// return true if we are less than the other key
func (hrst *HRSTKey) Less(other HRSTKey) bool {
	if hrst.Height < other.Height {
		return true
	}

	if hrst.Height > other.Height {
		return false
	}

	// height is equal, check round

	if hrst.Round < other.Round {
		return true
	}

	if hrst.Round > other.Round {
		return false
	}

	// round is equal, check step

	if hrst.Step < other.Step {
		return true
	}

	// HRS is greater or equal
	return false
}

type CosignerPeer struct {
	ID        int
	PublicKey rsa.PublicKey
}

type CosignerGetEphemeralSecretPartRequest struct {
	ChainID   string
	ID        int
	Height    int64
	Round     int64
	Step      int8
	Timestamp time.Time
}

// LocalCosigner responds to sign requests using their share key
// The cosigner maintains a watermark to avoid double-signing
//
// LocalCosigner signing is thread saafe
type LocalCosigner struct {
	config *RuntimeConfig

	pubKeyBytes []byte
	key         CosignerKey
	rsaKey      rsa.PrivateKey
	total       uint8
	threshold   uint8

	chainState map[string]ChainState

	peers map[int]CosignerPeer

	address string
}

func (cosigner *LocalCosigner) SaveLastSignedState(chainID string, signState SignStateConsensus) error {
	return cosigner.chainState[chainID].LastSignState.Save(
		signState,
		cosigner.chainState[chainID].lastSignStateMutex,
		true,
	)
}

func NewLocalCosigner(
	config *RuntimeConfig,
	cosignerKey CosignerKey,
	rsaKey rsa.PrivateKey,
	peers []CosignerPeer,
	address string,
	total uint8,
	threshold uint8,
) *LocalCosigner {
	cosigner := &LocalCosigner{
		config:     config,
		key:        cosignerKey,
		rsaKey:     rsaKey,
		chainState: make(map[string]ChainState),
		peers:      make(map[int]CosignerPeer),
		total:      total,
		threshold:  threshold,
		address:    address,
	}

	for _, peer := range peers {
		cosigner.peers[peer.ID] = peer
	}

	// cache the public key bytes for signing operations
	cosigner.pubKeyBytes = cosigner.key.PubKey.(tmcryptoed25519.PubKey)[:]

	return cosigner
}

// GetID returns the id of the cosigner
// Implements Cosigner interface
func (cosigner *LocalCosigner) GetID() int {
	return cosigner.key.ID
}

// GetAddress returns the RPC URL of the cosigner
// Implements Cosigner interface
func (cosigner *LocalCosigner) GetAddress() string {
	return cosigner.address
}

// Sign the sign request using the cosigner's share
// Return the signed bytes or an error
// Implements Cosigner interface
func (cosigner *LocalCosigner) sign(req CosignerSignRequest) (CosignerSignResponse, error) {
	chainID := req.ChainID
	// This function has multiple exit points.  Only start time can be guaranteed
	metricsTimeKeeper.SetPreviousLocalSignStart(time.Now())

	cosigner.chainState[chainID].lastSignStateMutex.Lock()
	defer cosigner.chainState[chainID].lastSignStateMutex.Unlock()

	res := CosignerSignResponse{}
	lss := cosigner.chainState[chainID].LastSignState

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

	meta, ok := cosigner.chainState[chainID].hrsMeta[hrst]
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
		req.SignBytes, cosigner.key.ShareKey, ephemeralShare, cosigner.pubKeyBytes, ephemeralPublic)

	cosigner.chainState[chainID].LastSignState.EphemeralPublic = ephemeralPublic
	err = cosigner.chainState[chainID].LastSignState.Save(SignStateConsensus{
		Height:    hrst.Height,
		Round:     hrst.Round,
		Step:      hrst.Step,
		Signature: sig,
		SignBytes: req.SignBytes,
	}, nil, true)

	if err != nil {
		if _, isSameHRSError := err.(*SameHRSError); !isSameHRSError {
			return res, err
		}
	}

	for existingKey := range cosigner.chainState[chainID].hrsMeta {
		// delete any HRS lower than our signed level
		// we will not be providing parts for any lower HRS
		if existingKey.Less(hrst) {
			delete(cosigner.chainState[chainID].hrsMeta, existingKey)
		}
	}

	res.EphemeralPublic = ephemeralPublic
	res.Signature = sig

	// Note - Function may return before this line so elapsed time for Finish may be multiple block times
	metricsTimeKeeper.SetPreviousLocalSignFinish(time.Now())

	return res, nil
}

func (cosigner *LocalCosigner) dealShares(req CosignerGetEphemeralSecretPartRequest) (HrsMetadata, error) {
	chainID := req.ChainID

	hrsKey := HRSTKey{
		Height:    req.Height,
		Round:     req.Round,
		Step:      req.Step,
		Timestamp: req.Timestamp.UnixNano(),
	}

	meta, ok := cosigner.chainState[chainID].hrsMeta[hrsKey]

	if ok {
		return meta, nil
	}

	secret := make([]byte, 32)
	if _, err := rand.Read(secret); err != nil {
		return HrsMetadata{}, err
	}

	meta = HrsMetadata{
		Secret: secret,
		Peers:  make([]PeerMetadata, cosigner.total),
	}

	// split this secret with shamirs
	// !! dealt shares need to be saved because dealing produces different shares each time!
	meta.DealtShares = tsed25519.DealShares(meta.Secret, cosigner.threshold, cosigner.total)

	cosigner.chainState[chainID].hrsMeta[hrsKey] = meta

	return meta, nil

}

func (cosigner *LocalCosigner) LoadSignStateIfNecessary(chainID string) error {
	if _, ok := cosigner.chainState[chainID]; ok {
		return nil
	}

	shareSignState, err := LoadOrCreateSignState(cosigner.config.ShareStateFile(chainID))
	if err != nil {
		return err
	}

	cosigner.chainState[chainID] = ChainState{
		LastSignState:      shareSignState,
		lastSignStateMutex: &sync.Mutex{},
		hrsMeta:            make(map[HRSTKey]HrsMetadata),
	}

	return nil
}

func (cosigner *LocalCosigner) GetEphemeralSecretParts(
	chainID string,
	hrst HRSTKey,
) (*CosignerEphemeralSecretPartsResponse, error) {
	metricsTimeKeeper.SetPreviousLocalEphemeralShare(time.Now())

	if err := cosigner.LoadSignStateIfNecessary(chainID); err != nil {
		return nil, err
	}

	res := &CosignerEphemeralSecretPartsResponse{
		EncryptedSecrets: make([]CosignerEphemeralSecretPart, 0, len(cosigner.peers)-1),
	}

	for _, peer := range cosigner.peers {
		if peer.ID == cosigner.GetID() {
			continue
		}
		secretPart, err := cosigner.getEphemeralSecretPart(CosignerGetEphemeralSecretPartRequest{
			ChainID:   chainID,
			ID:        peer.ID,
			Height:    hrst.Height,
			Round:     hrst.Round,
			Step:      hrst.Step,
			Timestamp: time.Unix(0, hrst.Timestamp),
		})

		if err != nil {
			return nil, err
		}

		res.EncryptedSecrets = append(res.EncryptedSecrets, secretPart)
	}
	return res, nil
}

// Get the ephemeral secret part for an ephemeral share
// The ephemeral secret part is encrypted for the receiver
func (cosigner *LocalCosigner) getEphemeralSecretPart(
	req CosignerGetEphemeralSecretPartRequest,
) (CosignerEphemeralSecretPart, error) {
	chainID := req.ChainID
	res := CosignerEphemeralSecretPart{}

	// protects the meta map
	cosigner.chainState[chainID].lastSignStateMutex.Lock()
	defer cosigner.chainState[chainID].lastSignStateMutex.Unlock()

	hrst := HRSTKey{
		Height:    req.Height,
		Round:     req.Round,
		Step:      req.Step,
		Timestamp: req.Timestamp.UnixNano(),
	}

	meta, ok := cosigner.chainState[chainID].hrsMeta[hrst]
	// generate metadata placeholder
	if !ok {
		newMeta, err := cosigner.dealShares(CosignerGetEphemeralSecretPartRequest{
			ChainID:   chainID,
			Height:    req.Height,
			Round:     req.Round,
			Step:      req.Step,
			Timestamp: req.Timestamp,
		})

		if err != nil {
			return res, err
		}

		meta = newMeta
		cosigner.chainState[chainID].hrsMeta[hrst] = meta
	}

	ourEphPublicKey := tsed25519.ScalarMultiplyBase(meta.Secret)

	// set our values
	meta.Peers[cosigner.key.ID-1].Share = meta.DealtShares[cosigner.key.ID-1]
	meta.Peers[cosigner.key.ID-1].EphemeralSecretPublicKey = ourEphPublicKey

	// grab the peer info for the ID being requested
	peer, ok := cosigner.peers[req.ID]
	if !ok {
		return res, errors.New("unknown peer ID")
	}

	sharePart := meta.DealtShares[req.ID-1]

	// use RSA public to encrypt user's share part
	encrypted, err := rsa.EncryptOAEP(sha256.New(), rand.Reader, &peer.PublicKey, sharePart, nil)
	if err != nil {
		return res, err
	}

	res.SourceID = cosigner.key.ID
	res.SourceEphemeralSecretPublicKey = ourEphPublicKey
	res.EncryptedSharePart = encrypted

	// sign the response payload with our private key
	// cosigners can verify the signature to confirm sender validity
	{
		jsonBytes, err := tmjson.Marshal(res)

		if err != nil {
			return res, err
		}

		digest := sha256.Sum256(jsonBytes)
		signature, err := rsa.SignPSS(rand.Reader, &cosigner.rsaKey, crypto.SHA256, digest[:], nil)
		if err != nil {
			return res, err
		}

		res.SourceSig = signature
	}

	res.DestinationID = req.ID

	return res, nil
}

// Store an ephemeral secret share part provided by another cosigner
func (cosigner *LocalCosigner) setEphemeralSecretPart(req CosignerSetEphemeralSecretPartRequest) error {
	chainID := req.ChainID

	// Verify the source signature
	if req.SourceSig == nil {
		return errors.New("SourceSig field is required")
	}

	digestMsg := CosignerEphemeralSecretPart{}
	digestMsg.SourceID = req.SourceID
	digestMsg.SourceEphemeralSecretPublicKey = req.SourceEphemeralSecretPublicKey
	digestMsg.EncryptedSharePart = req.EncryptedSharePart

	digestBytes, err := tmjson.Marshal(digestMsg)
	if err != nil {
		return err
	}

	digest := sha256.Sum256(digestBytes)
	peer, ok := cosigner.peers[req.SourceID]

	if !ok {
		return fmt.Errorf("unknown cosigner: %d", req.SourceID)
	}

	peerPub := peer.PublicKey
	err = rsa.VerifyPSS(&peerPub, crypto.SHA256, digest[:], req.SourceSig, nil)
	if err != nil {
		return err
	}

	// protects the meta map
	cosigner.chainState[chainID].lastSignStateMutex.Lock()
	defer cosigner.chainState[chainID].lastSignStateMutex.Unlock()

	hrst := HRSTKey{
		Height:    req.Height,
		Round:     req.Round,
		Step:      req.Step,
		Timestamp: req.Timestamp.UnixNano(),
	}

	meta, ok := cosigner.chainState[chainID].hrsMeta[hrst]
	// generate metadata placeholder
	if !ok {
		newMeta, err := cosigner.dealShares(CosignerGetEphemeralSecretPartRequest{
			ChainID: chainID,
			Height:  req.Height,
			Round:   req.Round,
			Step:    req.Step,
		})

		if err != nil {
			return err
		}

		meta = newMeta
		cosigner.chainState[chainID].hrsMeta[hrst] = meta
	}

	// decrypt share
	sharePart, err := rsa.DecryptOAEP(sha256.New(), rand.Reader, &cosigner.rsaKey, req.EncryptedSharePart, nil)
	if err != nil {
		return err
	}

	// set slot
	meta.Peers[req.SourceID-1].Share = sharePart
	meta.Peers[req.SourceID-1].EphemeralSecretPublicKey = req.SourceEphemeralSecretPublicKey
	return nil
}

func (cosigner *LocalCosigner) SetEphemeralSecretPartsAndSign(
	req CosignerSetEphemeralSecretPartsAndSignRequest) (*CosignerSignResponse, error) {
	chainID := req.ChainID

	if err := cosigner.LoadSignStateIfNecessary(chainID); err != nil {
		return nil, err
	}

	for _, secretPart := range req.EncryptedSecrets {
		err := cosigner.setEphemeralSecretPart(CosignerSetEphemeralSecretPartRequest{
			ChainID:                        chainID,
			SourceID:                       secretPart.SourceID,
			SourceEphemeralSecretPublicKey: secretPart.SourceEphemeralSecretPublicKey,
			EncryptedSharePart:             secretPart.EncryptedSharePart,
			SourceSig:                      secretPart.SourceSig,
			Height:                         req.HRST.Height,
			Round:                          req.HRST.Round,
			Step:                           req.HRST.Step,
			Timestamp:                      time.Unix(0, req.HRST.Timestamp),
		})
		if err != nil {
			return nil, err
		}
	}

	res, err := cosigner.sign(CosignerSignRequest{
		ChainID:   chainID,
		SignBytes: req.SignBytes,
	})
	return &res, err
}
