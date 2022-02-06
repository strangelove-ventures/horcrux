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

	tmCryptoEd25519 "github.com/tendermint/tendermint/crypto/ed25519"
	tmJson "github.com/tendermint/tendermint/libs/json"
	"gitlab.com/polychainlabs/edwards25519"
	tsed25519 "gitlab.com/polychainlabs/threshold-ed25519/pkg"
)

type HRSKey struct {
	Height int64
	Round  int64
	Step   int8
}

// return true if we are less than the other key
func (hrsKey *HRSKey) Less(other HRSKey) bool {
	if hrsKey.Height < other.Height {
		return true
	}

	if hrsKey.Height > other.Height {
		return false
	}

	// height is equal, check round

	if hrsKey.Round < other.Round {
		return true
	}

	if hrsKey.Round > other.Round {
		return false
	}

	// round is equal, check step

	if hrsKey.Step < other.Step {
		return true
	}

	// everything is equal
	return false
}

type CosignerPeer struct {
	ID        int
	PublicKey rsa.PublicKey
}

type CosignerGetEphemeralSecretPartRequest struct {
	ID     int
	Height int64
	Round  int64
	Step   int8
}

type LocalCosignerConfig struct {
	CosignerKey CosignerKey
	SignState   *SignState
	RsaKey      rsa.PrivateKey
	Peers       []CosignerPeer
	Address     string
	RaftAddress string
	Total       uint8
	Threshold   uint8
}

type PeerMetadata struct {
	Share                    []byte
	EphemeralSecretPublicKey []byte
}

type HrsMetadata struct {
	// need to be _total_ entries per player
	Secret      []byte
	DealtShares []tsed25519.Scalar
	Peers       []PeerMetadata
}

// LocalCosigner responds to sign requests using their share key
// The cosigner maintains a watermark to avoid double-signing
//
// LocalCosigner signing is thread saafe
type LocalCosigner struct {
	pubKeyBytes []byte
	key         CosignerKey
	rsaKey      rsa.PrivateKey
	total       uint8
	threshold   uint8

	// stores the last sign state for a share we have fully signed
	// incremented whenever we are asked to sign a share
	lastSignState *SignState

	// signing is thread safe
	lastSignStateMutex sync.Mutex

	// Height, Round, Step -> metadata
	hrsMeta map[HRSKey]HrsMetadata
	peers   map[int]CosignerPeer

	address     string
	raftAddress string
}

func (cosigner *LocalCosigner) GetErrorIfLessOrEqual(height int64, round int64, step int8) error {
	return cosigner.lastSignState.GetErrorIfLessOrEqual(height, round, step, &cosigner.lastSignStateMutex)
}

func (cosigner *LocalCosigner) SaveLastSignedState(signState SignStateConsensus) error {
	return cosigner.lastSignState.Save(signState, &cosigner.lastSignStateMutex)
}

func NewLocalCosigner(cfg LocalCosignerConfig) *LocalCosigner {
	cosigner := &LocalCosigner{
		key:           cfg.CosignerKey,
		lastSignState: cfg.SignState,
		rsaKey:        cfg.RsaKey,
		hrsMeta:       make(map[HRSKey]HrsMetadata),
		peers:         make(map[int]CosignerPeer),
		total:         cfg.Total,
		threshold:     cfg.Threshold,
		address:       cfg.Address,
		raftAddress:   cfg.RaftAddress,
	}

	for _, peer := range cfg.Peers {
		cosigner.peers[peer.ID] = peer
	}

	// cache the public key bytes for signing operations
	switch ed25519Key := cosigner.key.PubKey.(type) {
	case tmCryptoEd25519.PubKey:
		cosigner.pubKeyBytes = make([]byte, len(ed25519Key))
		copy(cosigner.pubKeyBytes, ed25519Key[:])
	default:
		panic("Not an ed25519 public key")
	}

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

// GetRaftAddress returns the Raft hostname of the cosigner
// Implements Cosigner interface
func (cosigner *LocalCosigner) GetRaftAddress() string {
	return cosigner.raftAddress
}

// Sign the sign request using the cosigner's share
// Return the signed bytes or an error
// Implements Cosigner interface
func (cosigner *LocalCosigner) sign(req CosignerSignRequest) (CosignerSignResponse, error) {
	cosigner.lastSignStateMutex.Lock()
	defer cosigner.lastSignStateMutex.Unlock()

	res := CosignerSignResponse{}
	lss := cosigner.lastSignState

	hrsKey, err := UnpackHRS(req.SignBytes)
	if err != nil {
		return res, err
	}

	sameHRS, err := lss.CheckHRS(hrsKey)
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
		} else if _, ok := lss.OnlyDifferByTimestamp(req.SignBytes); !ok {
			return res, errors.New("mismatched data")
		}

		// same HRS, and only differ by timestamp - ok to sign again
	}

	meta, ok := cosigner.hrsMeta[hrsKey]
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

	cosigner.lastSignState.EphemeralPublic = ephemeralPublic
	err = cosigner.lastSignState.Save(SignStateConsensus{
		Height:    hrsKey.Height,
		Round:     hrsKey.Round,
		Step:      hrsKey.Step,
		Signature: sig,
		SignBytes: req.SignBytes,
	}, nil)

	if err != nil {
		return res, err
	}

	for existingKey := range cosigner.hrsMeta {
		// delete any HRS lower than our signed level
		// we will not be providing parts for any lower HRS
		if existingKey.Less(hrsKey) {
			delete(cosigner.hrsMeta, existingKey)
		}
	}

	res.EphemeralPublic = ephemeralPublic
	res.Signature = sig
	return res, nil
}

func (cosigner *LocalCosigner) dealShares(req CosignerGetEphemeralSecretPartRequest) (HrsMetadata, error) {
	hrsKey := HRSKey{
		Height: req.Height,
		Round:  req.Round,
		Step:   req.Step,
	}

	meta, ok := cosigner.hrsMeta[hrsKey]

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

	cosigner.hrsMeta[hrsKey] = meta

	return meta, nil

}

func (cosigner *LocalCosigner) GetEphemeralSecretParts(
	req HRSKey) (*CosignerEphemeralSecretPartsResponse, error) {
	res := &CosignerEphemeralSecretPartsResponse{
		EncryptedSecrets: make([]CosignerEphemeralSecretPart, 0, len(cosigner.peers)-1),
	}
	for _, peer := range cosigner.peers {
		if peer.ID == cosigner.GetID() {
			continue
		}
		secretPart, err := cosigner.getEphemeralSecretPart(CosignerGetEphemeralSecretPartRequest{
			ID:     peer.ID,
			Height: req.Height,
			Round:  req.Round,
			Step:   req.Step,
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
	req CosignerGetEphemeralSecretPartRequest) (CosignerEphemeralSecretPart, error) {
	res := CosignerEphemeralSecretPart{}

	// protects the meta map
	cosigner.lastSignStateMutex.Lock()
	defer cosigner.lastSignStateMutex.Unlock()

	hrsKey := HRSKey{
		Height: req.Height,
		Round:  req.Round,
		Step:   req.Step,
	}

	meta, ok := cosigner.hrsMeta[hrsKey]
	// generate metadata placeholder
	if !ok {
		newMeta, err := cosigner.dealShares(CosignerGetEphemeralSecretPartRequest{
			Height: req.Height,
			Round:  req.Round,
			Step:   req.Step,
		})

		if err != nil {
			return res, err
		}

		meta = newMeta
		cosigner.hrsMeta[hrsKey] = meta
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
		jsonBytes, err := tmJson.Marshal(res)

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
		peer, ok := cosigner.peers[req.SourceID]

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
	cosigner.lastSignStateMutex.Lock()
	defer cosigner.lastSignStateMutex.Unlock()

	hrsKey := HRSKey{
		Height: req.Height,
		Round:  req.Round,
		Step:   req.Step,
	}

	meta, ok := cosigner.hrsMeta[hrsKey]
	// generate metadata placeholder
	if !ok {
		newMeta, err := cosigner.dealShares(CosignerGetEphemeralSecretPartRequest{
			Height: req.Height,
			Round:  req.Round,
			Step:   req.Step,
		})

		if err != nil {
			return err
		}

		meta = newMeta
		cosigner.hrsMeta[hrsKey] = meta
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
	for _, secretPart := range req.EncryptedSecrets {
		err := cosigner.setEphemeralSecretPart(CosignerSetEphemeralSecretPartRequest{
			SourceID:                       secretPart.SourceID,
			SourceEphemeralSecretPublicKey: secretPart.SourceEphemeralSecretPublicKey,
			EncryptedSharePart:             secretPart.EncryptedSharePart,
			SourceSig:                      secretPart.SourceSig,
			Height:                         req.HRS.Height,
			Round:                          req.HRS.Round,
			Step:                           req.HRS.Step,
		})
		if err != nil {
			return nil, err
		}
	}

	res, err := cosigner.sign(CosignerSignRequest{req.SignBytes})
	return &res, err
}
