package signer

import (
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
	cometlog "github.com/cometbft/cometbft/libs/log"
	"golang.org/x/sync/errgroup"
)

var _ Cosigner = &LocalCosigner{}

// LocalCosigner responds to sign requests using the key shard
// The cosigner maintains a watermark to avoid double-signing
//
// LocalCosigner signing is thread saafe
type LocalCosigner struct {
	logger        cometlog.Logger
	config        *RuntimeConfig
	key           CosignerRSAKey
	threshold     uint8
	chainState    sync.Map
	rsaPubKeys    map[int]CosignerRSAPubKey
	address       string
	pendingDiskWG sync.WaitGroup
}

func NewLocalCosigner(
	logger cometlog.Logger,
	config *RuntimeConfig,
	key CosignerRSAKey,
	rsaPubKeys []CosignerRSAPubKey,
	address string,
	threshold uint8,
) *LocalCosigner {
	cosigner := &LocalCosigner{
		logger:     logger,
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

type ChainState struct {
	// lastSignState stores the last sign state for an HRS we have fully signed
	// incremented whenever we are asked to sign an HRS
	lastSignState *SignState

	// Signing is thread safe - mutex is used for putting locks so only one goroutine can r/w to the function
	mu sync.RWMutex
	// signer generates nonces, combines nonces, signs, and verifies signatures.
	signer ThresholdSigner

	// Height, Round, Step -> metadata
	nonces map[HRSTKey][]Nonces
}

func (ccs *ChainState) combinedNonces(myID int, threshold uint8, hrst HRSTKey) ([]Nonce, error) {
	ccs.mu.RLock()
	defer ccs.mu.RUnlock()

	nonces, ok := ccs.nonces[hrst]
	if !ok {
		return nil, errors.New("no metadata at HRS")
	}

	combinedNonces := make([]Nonce, 0, threshold)

	// calculate secret and public keys
	for _, c := range nonces {
		if len(c.Shares) == 0 || len(c.Shares[myID-1]) == 0 {
			continue
		}

		combinedNonces = append(combinedNonces, Nonce{
			Share:  c.Shares[myID-1],
			PubKey: c.PubKey,
		})
	}

	return combinedNonces, nil
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

// Save updates the high watermark height/round/step (HRS) if it is greater
// than the current high watermark. A mutex is used to avoid concurrent state updates.
// The disk write is scheduled in a separate goroutine which will perform an atomic write.
// pendingDiskWG is used upon termination in pendingDiskWG to ensure all writes have completed.
func (cosigner *LocalCosigner) SaveLastSignedState(chainID string, signState SignStateConsensus) error {
	ccs, err := cosigner.getChainState(chainID)
	if err != nil {
		return err
	}

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

func (cosigner *LocalCosigner) getChainState(chainID string) (*ChainState, error) {
	cs, ok := cosigner.chainState.Load(chainID)
	if !ok {
		return nil, fmt.Errorf("failed to load chain state for %s", chainID)
	}

	ccs, ok := cs.(*ChainState)
	if !ok {
		return nil, fmt.Errorf("expected: (*ChainState), actual: (%T)", cs)
	}

	return ccs, nil
}

// GetPubKey returns public key of the validator.
// Implements Cosigner interface
func (cosigner *LocalCosigner) GetPubKey(chainID string) (cometcrypto.PubKey, error) {
	if err := cosigner.LoadSignStateIfNecessary(chainID); err != nil {
		return nil, err
	}

	ccs, err := cosigner.getChainState(chainID)
	if err != nil {
		return nil, err
	}

	return cometcryptoed25519.PubKey(ccs.signer.PubKey()), nil
}

// CombineSignatures combines partial signatures into a full signature.
func (cosigner *LocalCosigner) CombineSignatures(chainID string, signatures []PartialSignature) ([]byte, error) {
	ccs, err := cosigner.getChainState(chainID)
	if err != nil {
		return nil, err
	}

	return ccs.signer.CombineSignatures(signatures)
}

// VerifySignature validates a signed payload against the public key.
// Implements Cosigner interface
func (cosigner *LocalCosigner) VerifySignature(chainID string, payload, signature []byte) bool {
	if err := cosigner.LoadSignStateIfNecessary(chainID); err != nil {
		return false
	}

	ccs, err := cosigner.getChainState(chainID)
	if err != nil {
		return false
	}

	return cometcryptoed25519.PubKey(ccs.signer.PubKey()).VerifySignature(payload, signature)
}

// Sign the sign request using the cosigner's shard
// Return the signed bytes or an error
// Implements Cosigner interface
func (cosigner *LocalCosigner) sign(req CosignerSignRequest) (CosignerSignResponse, error) {
	chainID := req.ChainID

	res := CosignerSignResponse{}

	ccs, err := cosigner.getChainState(chainID)
	if err != nil {
		return res, err
	}

	// This function has multiple exit points.  Only start time can be guaranteed
	metricsTimeKeeper.SetPreviousLocalSignStart(time.Now())

	hrst, err := UnpackHRST(req.SignBytes)
	if err != nil {
		return res, err
	}

	existingSignature, err := ccs.lastSignState.existingSignatureOrErrorIfRegression(hrst, req.SignBytes)
	if err != nil {
		return res, err
	}

	if existingSignature != nil {
		res.Signature = existingSignature
		return res, nil
	}

	nonces, err := ccs.combinedNonces(cosigner.GetID(), uint8(cosigner.config.Config.ThresholdModeConfig.Threshold), hrst)
	if err != nil {
		return res, err
	}

	sig, err := ccs.signer.Sign(nonces, req.SignBytes)
	if err != nil {
		return res, err
	}

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

	ccs.mu.Lock()
	for existingKey := range ccs.nonces {
		// delete any HRS lower than our signed level
		// we will not be providing parts for any lower HRS
		if existingKey.HRSKey().LessThan(hrst.HRSKey()) {
			delete(ccs.nonces, existingKey)
		}
	}
	ccs.mu.Unlock()

	res.Signature = sig

	// Note - Function may return before this line so elapsed time for Finish may be multiple block times
	metricsTimeKeeper.SetPreviousLocalSignFinish(time.Now())

	return res, nil
}

func (cosigner *LocalCosigner) dealShares(req CosignerGetNonceRequest) ([]Nonces, error) {
	chainID := req.ChainID

	ccs, err := cosigner.getChainState(chainID)
	if err != nil {
		return nil, err
	}

	meta := make([]Nonces, len(cosigner.config.Config.ThresholdModeConfig.Cosigners))

	nonces, err := ccs.signer.GenerateNonces()
	if err != nil {
		return nil, err
	}

	meta[cosigner.GetID()-1] = nonces

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

	var signer ThresholdSigner

	signer, err = NewThresholdSignerSoft(cosigner.config, cosigner.GetID(), chainID)
	if err != nil {
		return err
	}

	cosigner.chainState.Store(chainID, &ChainState{
		lastSignState: signState,
		nonces:        make(map[HRSTKey][]Nonces),
		signer:        signer,
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

	cosigner.logger.Debug(
		"Generated nonces",
		"chain_id", chainID,
		"height", hrst.Height,
		"round", hrst.Round,
		"step", hrst.Step,
	)

	return res, nil
}

func (cosigner *LocalCosigner) dealSharesIfNecessary(chainID string, hrst HRSTKey) ([]Nonces, error) {
	ccs, err := cosigner.getChainState(chainID)
	if err != nil {
		return nil, err
	}

	// protects the meta map
	ccs.mu.Lock()
	defer ccs.mu.Unlock()

	nonces, ok := ccs.nonces[hrst]
	if ok {
		return nonces, nil
	}

	newNonces, err := cosigner.dealShares(CosignerGetNonceRequest{
		ChainID:   chainID,
		Height:    hrst.Height,
		Round:     hrst.Round,
		Step:      hrst.Step,
		Timestamp: time.Unix(0, hrst.Timestamp),
	})

	if err != nil {
		return nil, err
	}

	ccs.nonces[hrst] = newNonces
	return newNonces, nil
}

// Get the ephemeral secret part for an ephemeral share
// The ephemeral secret part is encrypted for the receiver
func (cosigner *LocalCosigner) getNonce(
	req CosignerGetNonceRequest,
) (CosignerNonce, error) {
	chainID := req.ChainID
	res := CosignerNonce{}

	hrst := HRSTKey{
		Height:    req.Height,
		Round:     req.Round,
		Step:      req.Step,
		Timestamp: req.Timestamp.UnixNano(),
	}

	id := cosigner.GetID()

	meta, err := cosigner.dealSharesIfNecessary(chainID, hrst)
	if err != nil {
		return res, err
	}

	ourCosignerMeta := meta[id-1]

	// grab the cosigner info for the ID being requested
	pubKey, ok := cosigner.rsaPubKeys[req.ID]
	if !ok {
		return res, errors.New("unknown cosigner ID")
	}

	// use RSA public to encrypt user's share part
	encrypted, err := rsa.EncryptOAEP(sha256.New(), rand.Reader, &pubKey.PublicKey, ourCosignerMeta.Shares[req.ID-1], nil)
	if err != nil {
		return res, err
	}

	res.SourceID = id
	res.PubKey = ourCosignerMeta.PubKey
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

// setNonce stores a nonce provided by another cosigner
func (cosigner *LocalCosigner) setNonce(req CosignerSetNonceRequest) error {
	chainID := req.ChainID

	ccs, err := cosigner.getChainState(chainID)
	if err != nil {
		return err
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

	// decrypt share
	nonceShare, err := rsa.DecryptOAEP(sha256.New(), rand.Reader, &cosigner.key.RSAKey, req.Share, nil)
	if err != nil {
		return err
	}

	hrst := HRSTKey{
		Height:    req.Height,
		Round:     req.Round,
		Step:      req.Step,
		Timestamp: req.Timestamp.UnixNano(),
	}

	// protects the meta map
	ccs.mu.Lock()
	defer ccs.mu.Unlock()

	nonces, ok := ccs.nonces[hrst]
	// generate metadata placeholder
	if !ok {
		return fmt.Errorf(
			"unexpected state, metadata does not exist for H: %d, R: %d, S: %d, T: %d",
			hrst.Height,
			hrst.Round,
			hrst.Step,
			hrst.Timestamp,
		)
	}

	// set slot
	if nonces[req.SourceID-1].Shares == nil {
		nonces[req.SourceID-1].Shares = make([][]byte, len(cosigner.config.Config.ThresholdModeConfig.Cosigners))
	}
	nonces[req.SourceID-1].Shares[cosigner.GetID()-1] = nonceShare
	nonces[req.SourceID-1].PubKey = req.PubKey

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
