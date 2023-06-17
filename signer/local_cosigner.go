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

	"github.com/coinbase/kryptology/pkg/ted25519/ted25519"
	cometcrypto "github.com/cometbft/cometbft/crypto"
	cometcryptoed25519 "github.com/cometbft/cometbft/crypto/ed25519"
	cometjson "github.com/cometbft/cometbft/libs/json"
)

var _ Cosigner = &LocalCosigner{}

type LastSignStateWrapper struct {
	// Signing is thread safe - lastSignStateMutex is used for putting locks so only one goroutine can r/w to the function
	mu sync.Mutex

	// lastSignState stores the last sign state for an HRS we have fully signed
	// incremented whenever we are asked to sign an HRS
	LastSignState *SignState
}

type ChainState struct {
	// Signing is thread safe - lastSignStateMutex is used for putting locks so only one goroutine can r/w to the function
	mu sync.Mutex

	// lastSignState stores the last sign state for an HRS we have fully signed
	// incremented whenever we are asked to sign an HRS
	lastSignState *SignState

	pubKeyBytes []byte
	keyShare    *ted25519.KeyShare

	// Height, Round, Step -> metadata
	hrsMeta map[HRSTKey][]CosignerMetadata
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

type CosignerRSAPubKey struct {
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

// LocalCosigner responds to sign requests using the key shard
// The cosigner maintains a watermark to avoid double-signing
//
// LocalCosigner signing is thread saafe
type LocalCosigner struct {
	config        *RuntimeConfig
	key           CosignerRSAKey
	threshold     uint8
	chainState    sync.Map
	rsaPubKeys    map[int]CosignerRSAPubKey
	address       string
	pendingDiskWG sync.WaitGroup
}

// Save updates the high watermark height/round/step (HRS) if it is greater
// than the current high watermark. A mutex is used to avoid concurrent state updates.
// The disk write is scheduled in a separate goroutine which will perform an atomic write.
// pendingDiskWG is used upon termination in pendingDiskWG to ensure all writes have completed.
func (cosigner *LocalCosigner) SaveLastSignedState(chainID string, signState SignStateConsensus) error {
	cs, ok := cosigner.chainState.Load(chainID)
	if !ok {
		return fmt.Errorf("failed to load chain state for %s", chainID)
	}

	ccs, ok := cs.(*ChainState)
	if !ok {
		return fmt.Errorf("expected: (*ChainState), actual: (%T)", cs)
	}

	ccs.mu.Lock()
	defer ccs.mu.Unlock()
	return ccs.lastSignState.Save(
		signState,
		&cosigner.pendingDiskWG,
	)
}

// waitForSignStatesToFlushToDisk waits for all state file writes queued
// in SaveLastSignedState to complete before termination.
func (cosigner *LocalCosigner) waitForSignStatesToFlushToDisk() {
	cosigner.pendingDiskWG.Wait()
}

func NewLocalCosigner(
	config *RuntimeConfig,
	key CosignerRSAKey,
	rsaPubKeys []CosignerRSAPubKey,
	address string,
	threshold uint8,
) *LocalCosigner {
	cosigner := &LocalCosigner{
		config:     config,
		key:        key,
		rsaPubKeys: make(map[int]CosignerRSAPubKey),
		threshold:  threshold,
		address:    address,
	}

	for _, pubKey := range rsaPubKeys {
		cosigner.rsaPubKeys[pubKey.ID] = pubKey
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

// GetPubKey returns public key of the validator.
// Implements Cosigner interface
func (cosigner *LocalCosigner) GetPubKey(chainID string) (cometcrypto.PubKey, error) {
	if err := cosigner.LoadSignStateIfNecessary(chainID); err != nil {
		return nil, err
	}

	cs, ok := cosigner.chainState.Load(chainID)
	if !ok {
		return nil, fmt.Errorf("failed to load chain state for %s", chainID)
	}

	ccs, ok := cs.(*ChainState)
	if !ok {
		return nil, fmt.Errorf("expected: (*ChainState), actual: (%T)", cs)
	}

	return cometcryptoed25519.PubKey(ccs.pubKeyBytes), nil
}

// VerifySignature validates a signed payload against the public key.
// Implements Cosigner interface
func (cosigner *LocalCosigner) VerifySignature(chainID string, payload, signature []byte) bool {
	if err := cosigner.LoadSignStateIfNecessary(chainID); err != nil {
		return false
	}

	cs, ok := cosigner.chainState.Load(chainID)
	if !ok {
		return false
	}

	ccs, ok := cs.(*ChainState)
	if !ok {
		return false
	}

	return cometcryptoed25519.PubKey(ccs.pubKeyBytes).VerifySignature(payload, signature)
}

// Sign the sign request using the cosigner's shard
// Return the signed bytes or an error
// Implements Cosigner interface
func (cosigner *LocalCosigner) sign(req CosignerSignRequest) (CosignerSignResponse, error) {
	chainID := req.ChainID

	res := CosignerSignResponse{}

	cs, ok := cosigner.chainState.Load(chainID)
	if !ok {
		return res, fmt.Errorf("failed to load chain state for %s", chainID)
	}

	ccs, ok := cs.(*ChainState)
	if !ok {
		return res, fmt.Errorf("expected: (*ChainState), actual: (%T)", cs)
	}

	// This function has multiple exit points.  Only start time can be guaranteed
	metricsTimeKeeper.SetPreviousLocalSignStart(time.Now())

	ccs.mu.Lock()
	defer ccs.mu.Unlock()

	lss := ccs.lastSignState

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
			res.Signature = lss.Signature
			return res, nil
		} else if err := lss.OnlyDifferByTimestamp(req.SignBytes); err != nil {
			return res, err
		}

		// same HRS, and only differ by timestamp - ok to sign again
	}

	meta, ok := ccs.hrsMeta[hrst]
	if !ok {
		return res, errors.New("no metadata at HRS")
	}

	var nonceShare *ted25519.NonceShare
	var noncePub ted25519.PublicKey

	myID := cosigner.GetID()

	// calculate secret and public keys
	for _, c := range meta {
		if len(c.Shares) == 0 || len(c.Shares[myID-1]) == 0 {
			continue
		}

		thisNonce := ted25519.NonceShareFromBytes(c.Shares[myID-1])
		if nonceShare == nil {
			nonceShare = thisNonce
		} else {
			nonceShare = nonceShare.Add(thisNonce)
		}

		if len(noncePub) == 0 {
			noncePub = c.EphemeralSecretPublicKey
		} else {
			noncePub = ted25519.GeAdd(noncePub, c.EphemeralSecretPublicKey)
		}
	}

	sig := ted25519.TSign(req.SignBytes, ccs.keyShare, ted25519.PublicKey(ccs.pubKeyBytes), nonceShare, noncePub)

	ccs.lastSignState.EphemeralPublic = noncePub

	err = ccs.lastSignState.Save(SignStateConsensus{
		Height:    hrst.Height,
		Round:     hrst.Round,
		Step:      hrst.Step,
		Signature: sig.Bytes(),
		SignBytes: req.SignBytes,
	}, &cosigner.pendingDiskWG)

	if err != nil {
		if _, isSameHRSError := err.(*SameHRSError); !isSameHRSError {
			return res, err
		}
	}

	for existingKey := range ccs.hrsMeta {
		// delete any HRS lower than our signed level
		// we will not be providing parts for any lower HRS
		if existingKey.Less(hrst) {
			delete(ccs.hrsMeta, existingKey)
		}
	}

	res.Signature = sig.Bytes()

	// Note - Function may return before this line so elapsed time for Finish may be multiple block times
	metricsTimeKeeper.SetPreviousLocalSignFinish(time.Now())

	return res, nil
}

func (cosigner *LocalCosigner) dealShares(req CosignerGetEphemeralSecretPartRequest) ([]CosignerMetadata, error) {
	chainID := req.ChainID

	cs, ok := cosigner.chainState.Load(chainID)
	if !ok {
		return nil, fmt.Errorf("failed to load chain state for %s", chainID)
	}

	ccs, ok := cs.(*ChainState)
	if !ok {
		return nil, fmt.Errorf("expected: (*ChainState), actual: (%T)", cs)
	}

	hrsKey := HRSTKey{
		Height:    req.Height,
		Round:     req.Round,
		Step:      req.Step,
		Timestamp: req.Timestamp.UnixNano(),
	}

	meta, ok := ccs.hrsMeta[hrsKey]

	if ok {
		return meta, nil
	}

	total := len(cosigner.rsaPubKeys)

	meta = make([]CosignerMetadata, total)

	noncePub, nonceShares, _, err := ted25519.GenerateSharedNonce(&ted25519.ShareConfiguration{T: int(cosigner.threshold), N: total}, ccs.keyShare, ccs.pubKeyBytes, ted25519.Message{})
	if err != nil {
		return nil, fmt.Errorf("failed to generate nonce shares: %w", err)
	}

	shares := make([][]byte, total)
	for i, s := range nonceShares {
		shares[i] = s.Bytes()
	}

	meta[cosigner.GetID()-1] = CosignerMetadata{
		Shares:                   shares,
		EphemeralSecretPublicKey: noncePub.Bytes(),
	}

	ccs.hrsMeta[hrsKey] = meta

	return meta, nil

}

func (cosigner *LocalCosigner) LoadSignStateIfNecessary(chainID string) error {
	if chainID == "" {
		return fmt.Errorf("chain id cannot be empty")
	}

	if _, ok := cosigner.chainState.Load(chainID); ok {
		return nil
	}

	signState, err := LoadOrCreateSignState(cosigner.config.CosignerStateFile(chainID))
	if err != nil {
		return err
	}

	keyFile, err := cosigner.config.KeyFileExistsCosigner(chainID)
	if err != nil {
		return err
	}

	key, err := LoadCosignerEd25519Key(keyFile)
	if err != nil {
		return fmt.Errorf("error reading cosigner key: %s", err)
	}

	if key.ID != cosigner.GetID() {
		return fmt.Errorf("key shard ID (%d) in (%s) does not match cosigner ID (%d)", key.ID, keyFile, cosigner.GetID())
	}

	cosigner.chainState.Store(chainID, &ChainState{
		lastSignState: signState,
		hrsMeta:       make(map[HRSTKey][]CosignerMetadata),
		keyShare:      ted25519.NewKeyShare(byte(key.ID), reverseBytes(key.PrivateShard)),
		pubKeyBytes:   key.PubKey.(cometcryptoed25519.PubKey)[:],
	})

	return nil
}

// reverseBytes returns a new slice of the input bytes reversed
func reverseBytes(inBytes []byte) []byte {
	outBytes := make([]byte, len(inBytes))

	for i, j := 0, len(inBytes)-1; j >= 0; i, j = i+1, j-1 {
		outBytes[i] = inBytes[j]
	}

	return outBytes
}

func (cosigner *LocalCosigner) GetEphemeralSecretParts(
	chainID string,
	hrst HRSTKey,
) (*CosignerEphemeralSecretPartsResponse, error) {
	metricsTimeKeeper.SetPreviousLocalEphemeralShare(time.Now())

	start := time.Now()

	if err := cosigner.LoadSignStateIfNecessary(chainID); err != nil {
		return nil, err
	}

	postLoadSignState := time.Since(start)

	fmt.Printf("time to load sign state: %.02f\n",
		float64(postLoadSignState.Microseconds())/1000.0,
	)

	res := &CosignerEphemeralSecretPartsResponse{
		EncryptedSecrets: make([]CosignerEphemeralSecretPart, 0, len(cosigner.rsaPubKeys)-1),
	}

	id := cosigner.GetID()

	for _, pubKey := range cosigner.rsaPubKeys {
		if pubKey.ID == id {
			continue
		}
		getEphSecretPartStart := time.Now()
		secretPart, err := cosigner.getEphemeralSecretPart(CosignerGetEphemeralSecretPartRequest{
			ChainID:   chainID,
			ID:        pubKey.ID,
			Height:    hrst.Height,
			Round:     hrst.Round,
			Step:      hrst.Step,
			Timestamp: time.Unix(0, hrst.Timestamp),
		})

		if err != nil {
			return nil, err
		}

		durationGetEphSecretPart := time.Since(getEphSecretPartStart)
		fmt.Printf("[%d] time to get eph secret part for [%d]: %.02f\n",
			id,
			pubKey.ID,
			float64(durationGetEphSecretPart.Microseconds())/1000.0,
		)

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

	cs, ok := cosigner.chainState.Load(chainID)
	if !ok {
		return res, fmt.Errorf("failed to load chain state for %s", chainID)
	}

	ccs, ok := cs.(*ChainState)
	if !ok {
		return res, fmt.Errorf("expected: (*ChainState), actual: (%T)", cs)
	}

	// protects the meta map
	ccs.mu.Lock()
	defer ccs.mu.Unlock()

	hrst := HRSTKey{
		Height:    req.Height,
		Round:     req.Round,
		Step:      req.Step,
		Timestamp: req.Timestamp.UnixNano(),
	}

	id := cosigner.GetID()

	meta, ok := ccs.hrsMeta[hrst]
	// generate metadata placeholder
	if !ok {
		preDealShares := time.Now()
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

		timeDealShares := time.Since(preDealShares)

		fmt.Printf("[%d] time to deal shares: %.02f\n", id, float64(timeDealShares.Microseconds())/1000.0)

		meta = newMeta
		ccs.hrsMeta[hrst] = meta
	}

	ourCosignerMeta := meta[id-1]

	// grab the cosigner info for the ID being requested
	pubKey, ok := cosigner.rsaPubKeys[req.ID]
	if !ok {
		return res, errors.New("unknown cosigner ID")
	}

	sharePart := ourCosignerMeta.Shares[req.ID-1]

	preEncrypt := time.Now()

	// use RSA public to encrypt user's share part
	encrypted, err := rsa.EncryptOAEP(sha256.New(), rand.Reader, &pubKey.PublicKey, sharePart, nil)
	if err != nil {
		return res, err
	}

	postEncrypt := time.Since(preEncrypt)

	fmt.Printf("[%d] time to rsa encrypt: %.02f\n",
		id,
		float64(postEncrypt.Microseconds())/1000.0,
	)

	res.SourceID = id
	res.SourceEphemeralSecretPublicKey = ourCosignerMeta.EphemeralSecretPublicKey
	res.EncryptedSharePart = encrypted

	// sign the response payload with our private key
	// cosigners can verify the signature to confirm sender validity
	{
		preSign := time.Now()

		jsonBytes, err := cometjson.Marshal(res)

		if err != nil {
			return res, err
		}

		digest := sha256.Sum256(jsonBytes)
		signature, err := rsa.SignPSS(rand.Reader, &cosigner.key.RSAKey, crypto.SHA256, digest[:], nil)
		if err != nil {
			return res, err
		}

		postSign := time.Since(preSign)

		fmt.Printf("[%d] time to rsa sign: %.02f\n",
			id,
			float64(postSign.Microseconds())/1000.0,
		)

		res.SourceSig = signature
	}

	res.DestinationID = req.ID

	return res, nil
}

// Store an ephemeral secret share part provided by another cosigner
func (cosigner *LocalCosigner) setEphemeralSecretPart(req CosignerSetEphemeralSecretPartRequest) error {
	chainID := req.ChainID

	cs, ok := cosigner.chainState.Load(chainID)
	if !ok {
		return fmt.Errorf("failed to load chain state for %s", chainID)
	}

	ccs, ok := cs.(*ChainState)
	if !ok {
		return fmt.Errorf("expected: (*ChainState), actual: (%T)", cs)
	}

	// Verify the source signature
	if req.SourceSig == nil {
		return errors.New("SourceSig field is required")
	}

	digestMsg := CosignerEphemeralSecretPart{
		SourceID:                       req.SourceID,
		SourceEphemeralSecretPublicKey: req.SourceEphemeralSecretPublicKey,
		EncryptedSharePart:             req.EncryptedSharePart,
	}

	digestBytes, err := cometjson.Marshal(digestMsg)
	if err != nil {
		return err
	}

	digest := sha256.Sum256(digestBytes)
	pubKey, ok := cosigner.rsaPubKeys[req.SourceID]

	if !ok {
		return fmt.Errorf("unknown cosigner: %d", req.SourceID)
	}

	err = rsa.VerifyPSS(&pubKey.PublicKey, crypto.SHA256, digest[:], req.SourceSig, nil)
	if err != nil {
		return err
	}

	// protects the meta map
	ccs.mu.Lock()
	defer ccs.mu.Unlock()

	hrst := HRSTKey{
		Height:    req.Height,
		Round:     req.Round,
		Step:      req.Step,
		Timestamp: req.Timestamp.UnixNano(),
	}

	meta, ok := ccs.hrsMeta[hrst]
	// generate metadata placeholder
	if !ok {
		return fmt.Errorf(
			"unexpected state, metadata for hrs does not exist for H: %d, R: %d, S: %d, T: %d",
			hrst.Height,
			hrst.Round,
			hrst.Step,
			hrst.Timestamp,
		)
	}

	// decrypt share
	sharePart, err := rsa.DecryptOAEP(sha256.New(), rand.Reader, &cosigner.key.RSAKey, req.EncryptedSharePart, nil)
	if err != nil {
		return err
	}

	// set slot
	if meta[req.SourceID-1].Shares == nil {
		meta[req.SourceID-1].Shares = make([][]byte, len(cosigner.rsaPubKeys))
	}
	meta[req.SourceID-1].Shares[cosigner.GetID()-1] = sharePart
	meta[req.SourceID-1].EphemeralSecretPublicKey = req.SourceEphemeralSecretPublicKey
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
