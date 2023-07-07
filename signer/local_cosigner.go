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

	cometcrypto "github.com/cometbft/cometbft/crypto"
	cometcryptoed25519 "github.com/cometbft/cometbft/crypto/ed25519"
	cometjson "github.com/cometbft/cometbft/libs/json"
	"gitlab.com/unit410/edwards25519"
	tsed25519 "gitlab.com/unit410/threshold-ed25519/pkg"
	"golang.org/x/sync/errgroup"
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
	key         CosignerEd25519Key

	// Height, Round, Step -> metadata
	hrsMeta map[HRSTKey]HrsMetadata
}

type CosignerRSAPubKey struct {
	ID        int
	PublicKey rsa.PublicKey
}

type CosignerGetNonceRequest struct {
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

	return ccs.key.PubKey, nil
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

	return ccs.key.PubKey.VerifySignature(payload, signature)
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
			res.NoncePublic = lss.NoncePublic
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

	shareParts := make([]tsed25519.Scalar, 0)
	publicKeys := make([]tsed25519.Element, 0)

	// calculate secret and public keys
	for _, c := range meta.Cosigners {
		if len(c.Share) == 0 {
			continue
		}
		shareParts = append(shareParts, c.Share)
		publicKeys = append(publicKeys, c.NoncePublicKey)
	}

	nonceShare := tsed25519.AddScalars(shareParts)
	noncePublic := tsed25519.AddElements(publicKeys)

	// check bounds for ephemeral share to avoid passing out of bounds valids to SignWithShare
	if len(nonceShare) != 32 {
		return res, errors.New("ephemeral share is out of bounds")
	}

	var scalarBytes [32]byte
	copy(scalarBytes[:], nonceShare)
	if !edwards25519.ScMinimal(&scalarBytes) {
		return res, errors.New("ephemeral share is out of bounds")
	}

	sig := tsed25519.SignWithShare(
		req.SignBytes, ccs.key.PrivateShard, nonceShare, ccs.pubKeyBytes, noncePublic)

	ccs.lastSignState.NoncePublic = noncePublic
	err = ccs.lastSignState.Save(SignStateConsensus{
		Height:    hrst.Height,
		Round:     hrst.Round,
		Step:      hrst.Step,
		Signature: sig,
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
		if existingKey.HRSKey().LessThan(hrst.HRSKey()) {
			delete(ccs.hrsMeta, existingKey)
		}
	}

	res.NoncePublic = noncePublic
	res.Signature = sig

	// Note - Function may return before this line so elapsed time for Finish may be multiple block times
	metricsTimeKeeper.SetPreviousLocalSignFinish(time.Now())

	return res, nil
}

func (cosigner *LocalCosigner) dealShares(req CosignerGetNonceRequest) (HrsMetadata, error) {
	chainID := req.ChainID

	cs, ok := cosigner.chainState.Load(chainID)
	if !ok {
		return HrsMetadata{}, fmt.Errorf("failed to load chain state for %s", chainID)
	}

	ccs, ok := cs.(*ChainState)
	if !ok {
		return HrsMetadata{}, fmt.Errorf("expected: (*ChainState), actual: (%T)", cs)
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

	secret := make([]byte, 32)
	if _, err := rand.Read(secret); err != nil {
		return HrsMetadata{}, err
	}

	total := len(cosigner.rsaPubKeys)

	meta = HrsMetadata{
		Secret:    secret,
		Cosigners: make([]CosignerMetadata, total),
	}

	// split this secret with shamirs
	// !! dealt shares need to be saved because dealing produces different shares each time!
	meta.DealtShares = tsed25519.DealShares(meta.Secret, cosigner.threshold, uint8(total))

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
		hrsMeta:       make(map[HRSTKey]HrsMetadata),
		// cache the public key bytes for signing operations
		key:         key,
		pubKeyBytes: key.PubKey.(cometcryptoed25519.PubKey)[:],
	})

	return nil
}

func (cosigner *LocalCosigner) GetNonces(
	chainID string,
	hrst HRSTKey,
) (*CosignerNoncesResponse, error) {
	metricsTimeKeeper.SetPreviousLocalNonce(time.Now())

	if err := cosigner.LoadSignStateIfNecessary(chainID); err != nil {
		return nil, err
	}

	res := &CosignerNoncesResponse{
		Nonces: make([]CosignerNonce, len(cosigner.rsaPubKeys)-1),
	}

	id := cosigner.GetID()

	var eg errgroup.Group
	// getting nonces requires encrypting and signing for each cosigner,
	// so we perform these operations in parallel.

	for peerID := range cosigner.rsaPubKeys {
		if peerID == id {
			continue
		}

		peerID := peerID

		eg.Go(func() error {
			secretPart, err := cosigner.getNonce(CosignerGetNonceRequest{
				ChainID:   chainID,
				ID:        peerID,
				Height:    hrst.Height,
				Round:     hrst.Round,
				Step:      hrst.Step,
				Timestamp: time.Unix(0, hrst.Timestamp),
			})

			idx := peerID - 1

			if idx >= id {
				res.Nonces[idx-1] = secretPart
			} else {
				res.Nonces[idx] = secretPart
			}

			return err
		})
	}

	if err := eg.Wait(); err != nil {
		return nil, err
	}

	return res, nil
}

// Get the ephemeral secret part for an ephemeral share
// The ephemeral secret part is encrypted for the receiver
func (cosigner *LocalCosigner) getNonce(
	req CosignerGetNonceRequest,
) (CosignerNonce, error) {
	chainID := req.ChainID
	res := CosignerNonce{}

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

	meta, ok := ccs.hrsMeta[hrst]
	// generate metadata placeholder
	if !ok {
		newMeta, err := cosigner.dealShares(CosignerGetNonceRequest{
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
		ccs.hrsMeta[hrst] = meta
	}

	ourEphPublicKey := tsed25519.ScalarMultiplyBase(meta.Secret)

	id := ccs.key.ID

	// set our values
	meta.Cosigners[id-1].Share = meta.DealtShares[id-1]
	meta.Cosigners[id-1].NoncePublicKey = ourEphPublicKey

	// grab the cosigner info for the ID being requested
	pubKey, ok := cosigner.rsaPubKeys[req.ID]
	if !ok {
		return res, errors.New("unknown cosigner ID")
	}

	sharePart := meta.DealtShares[req.ID-1]

	// use RSA public to encrypt user's share part
	encrypted, err := rsa.EncryptOAEP(sha256.New(), rand.Reader, &pubKey.PublicKey, sharePart, nil)
	if err != nil {
		return res, err
	}

	res.SourceID = id
	res.PubKey = ourEphPublicKey
	res.Share = encrypted

	// Sign the response payload with our private key.
	// Cosigners can verify the signature to authenticate the sender.
	jsonBytes, err := cometjson.Marshal(res)

	if err != nil {
		return res, err
	}

	digest := sha256.Sum256(jsonBytes)
	signature, err := rsa.SignPSS(rand.Reader, &cosigner.key.RSAKey, crypto.SHA256, digest[:], nil)
	if err != nil {
		return res, err
	}

	res.Signature = signature

	res.DestinationID = req.ID

	return res, nil
}

// Store an ephemeral secret share part provided by another cosigner
func (cosigner *LocalCosigner) setNonce(req CosignerSetNonceRequest) error {
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
	if req.Signature == nil {
		return errors.New("signature field is required")
	}

	digestMsg := CosignerNonce{
		SourceID: req.SourceID,
		PubKey:   req.PubKey,
		Share:    req.Share,
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

	err = rsa.VerifyPSS(&pubKey.PublicKey, crypto.SHA256, digest[:], req.Signature, nil)
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
		newMeta, err := cosigner.dealShares(CosignerGetNonceRequest{
			ChainID: chainID,
			Height:  req.Height,
			Round:   req.Round,
			Step:    req.Step,
		})

		if err != nil {
			return err
		}

		meta = newMeta
		ccs.hrsMeta[hrst] = meta
	}

	// decrypt share
	sharePart, err := rsa.DecryptOAEP(sha256.New(), rand.Reader, &cosigner.key.RSAKey, req.Share, nil)
	if err != nil {
		return err
	}

	// set slot
	meta.Cosigners[req.SourceID-1].Share = sharePart
	meta.Cosigners[req.SourceID-1].NoncePublicKey = req.PubKey
	return nil
}

func (cosigner *LocalCosigner) SetNoncesAndSign(
	req CosignerSetNoncesAndSignRequest) (*CosignerSignResponse, error) {
	chainID := req.ChainID

	if err := cosigner.LoadSignStateIfNecessary(chainID); err != nil {
		return nil, err
	}

	var eg errgroup.Group

	// setting nonces requires decrypting and verifying signature from each cosigner,
	// so we perform these operations in parallel.

	for _, secretPart := range req.Nonces {
		secretPart := secretPart

		eg.Go(func() error {
			return cosigner.setNonce(CosignerSetNonceRequest{
				ChainID:   chainID,
				SourceID:  secretPart.SourceID,
				PubKey:    secretPart.PubKey,
				Share:     secretPart.Share,
				Signature: secretPart.Signature,
				Height:    req.HRST.Height,
				Round:     req.HRST.Round,
				Step:      req.HRST.Step,
				Timestamp: time.Unix(0, req.HRST.Timestamp),
			})
		})
	}

	if err := eg.Wait(); err != nil {
		return nil, err
	}

	res, err := cosigner.sign(CosignerSignRequest{
		ChainID:   chainID,
		SignBytes: req.SignBytes,
	})
	return &res, err
}
