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

type LocalCosignerConfig struct {
	CosignerKey CosignerKey
	SignState   *SignState
	RsaKey      rsa.PrivateKey
	Peers       []CosignerPeer
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
	}

	for _, peer := range cfg.Peers {
		cosigner.peers[peer.ID] = peer
	}

	// cache the public key bytes for signing operations
	switch ed25519Key := cosigner.key.PubKey.(type) {
	case tmCryptoEd25519.PubKey:
		cosigner.pubKeyBytes = make([]byte, len(ed25519Key))
		copy(cosigner.pubKeyBytes[:], ed25519Key[:])
		break
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

// Sign the sign request using the cosigner's share
// Return the signed bytes or an error
// Implements Cosigner interface
func (cosigner *LocalCosigner) Sign(req CosignerSignRequest) (CosignerSignResponse, error) {
	cosigner.lastSignStateMutex.Lock()
	defer cosigner.lastSignStateMutex.Unlock()

	res := CosignerSignResponse{}
	lss := cosigner.lastSignState

	height, round, step, err := UnpackHRS(req.SignBytes)
	if err != nil {
		return res, err
	}

	sameHRS, err := lss.CheckHRS(height, round, step)
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
			return res, errors.New("Mismatched data")
		}

		// saame HRS, and only differ by timestamp - ok to sign again
	}

	hrsKey := HRSKey{
		Height: height,
		Round:  round,
		Step:   step,
	}
	meta, ok := cosigner.hrsMeta[hrsKey]
	if !ok {
		return res, errors.New("No metadata at HRS")
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
			return res, errors.New("Ephemeral share is out of bounds.")
		}

		var scalarBytes [32]byte
		copy(scalarBytes[:], ephemeralShare)
		if !edwards25519.ScMinimal(&scalarBytes) {
			return res, errors.New("Ephemeral share is out of bounds.")
		}
	}

	share := cosigner.key.ShareKey[:]
	sig := tsed25519.SignWithShare(req.SignBytes, share, ephemeralShare, cosigner.pubKeyBytes, ephemeralPublic)

	cosigner.lastSignState.Height = height
	cosigner.lastSignState.Round = round
	cosigner.lastSignState.Step = step
	cosigner.lastSignState.EphemeralPublic = ephemeralPublic
	cosigner.lastSignState.Signature = sig
	cosigner.lastSignState.SignBytes = req.SignBytes
	cosigner.lastSignState.Save()

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

// Get the ephemeral secret part for an ephemeral share
// The ephemeral secret part is encrypted for the receiver
func (cosigner *LocalCosigner) GetEphemeralSecretPart(req CosignerGetEphemeralSecretPartRequest) (CosignerGetEphemeralSecretPartResponse, error) {
	res := CosignerGetEphemeralSecretPartResponse{}

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
		secret := make([]byte, 32)
		rand.Read(secret)

		meta = HrsMetadata{
			Secret: secret,
			Peers:  make([]PeerMetadata, cosigner.total),
		}

		// split this secret with shamirs
		// !! dealt shares need to be saved because dealing produces different shares each time!
		meta.DealtShares = tsed25519.DealShares(meta.Secret, cosigner.threshold, cosigner.total)

		cosigner.hrsMeta[hrsKey] = meta
	}

	ourEphPublicKey := tsed25519.ScalarMultiplyBase(meta.Secret)

	// set our values
	meta.Peers[cosigner.key.ID-1].Share = meta.DealtShares[cosigner.key.ID-1]
	meta.Peers[cosigner.key.ID-1].EphemeralSecretPublicKey = ourEphPublicKey

	// grab the peer info for the ID being requested
	peer, ok := cosigner.peers[req.ID]
	if !ok {
		return res, errors.New("Unknown peer ID")
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

	return res, nil
}

func (cosigner *LocalCosigner) HasEphemeralSecretPart(req CosignerHasEphemeralSecretPartRequest) (CosignerHasEphemeralSecretPartResponse, error) {
	res := CosignerHasEphemeralSecretPartResponse{
		Exists: false,
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
	if ok {
		pub := meta.Peers[req.ID-1].EphemeralSecretPublicKey
		if len(pub) > 0 {
			res.Exists = true
			res.EphemeralSecretPublicKey = pub
		}
	}

	return res, nil
}

// Store an ephemeral secret share part provided by another cosigner
func (cosigner *LocalCosigner) SetEphemeralSecretPart(req CosignerSetEphemeralSecretPartRequest) error {

	// Verify the source signature
	{
		if req.SourceSig == nil {
			return errors.New("SourceSig field is required")
		}

		digestMsg := CosignerGetEphemeralSecretPartResponse{}
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
			return fmt.Errorf("Unknown cosigner: %d", req.SourceID)
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
		secret := make([]byte, 32)
		rand.Read(secret)

		meta = HrsMetadata{
			Secret: secret,
			Peers:  make([]PeerMetadata, cosigner.total),
		}

		meta.DealtShares = tsed25519.DealShares(meta.Secret, cosigner.threshold, cosigner.total)

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
