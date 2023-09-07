package cosigner

import (
	"errors"
	"fmt"

	"github.com/strangelove-ventures/horcrux/pkg/types"

	"sync"
	"time"

	"github.com/strangelove-ventures/horcrux/pkg/metrics"

	cometcrypto "github.com/cometbft/cometbft/crypto"
	cometcryptoed25519 "github.com/cometbft/cometbft/crypto/ed25519"
	cometlog "github.com/cometbft/cometbft/libs/log"
	"golang.org/x/sync/errgroup"
)

type SetNonceRequest struct {
	ChainID   string
	SourceID  int
	PubKey    []byte
	Share     []byte
	Signature []byte
	Height    int64
	Round     int64
	Step      int8
	Timestamp time.Time
}

type GetNonceRequest struct {
	ChainID   string
	ID        int
	Height    int64
	Round     int64
	Step      int8
	Timestamp time.Time
}

// LocalCosigner "responds" to sign requests from RemoteCosigner
//   - LocalCosigner maintains a high watermark to avoid double-signing.
//   - Signing is thread safe.
//   - LocalCosigner implements the ICosigner interface
type LocalCosigner struct {
	logger        cometlog.Logger
	Config        *RuntimeConfig
	security      ICosignerSecurity
	chainStateMap sync.Map // chainstate is a used for map[ChainID] -> *ChainState
	address       string   // ip address of the cosigner
	pendingDiskWG sync.WaitGroup
}

func NewLocalCosigner(
	logger cometlog.Logger,
	config *RuntimeConfig,
	security ICosignerSecurity,
	address string,
) *LocalCosigner {
	return &LocalCosigner{
		logger:   logger,
		Config:   config,
		security: security,
		address:  address,
	}
}

// ChainState
type ChainState struct {
	// lastSignState stores the last sign state for an HRS we have fully signed
	// incremented whenever we are asked to sign an HRS
	lastSignState *types.SignState

	// Signing is thread safe - mutex is used for putting locks so only one goroutine can r/w to the ChainState
	mu sync.RWMutex
	// signer generates nonces, combines nonces, signs, and verifies signatures.
	signer IThresholdSigner

	// Height, Round, Step -> metadata
	nonces map[types.HRSTKey][]Nonces
}

func (ccs *ChainState) combinedNonces(myID int, threshold uint8, hrst types.HRSTKey) ([]Nonce, error) {
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

// SaveLastSignedState updates the high watermark height/round/step (HRS) if it is greater
// than the current high watermark. A mutex is used to avoid concurrent state updates.
// The disk write is scheduled in a separate goroutine which will perform an atomic write.
// pendingDiskWG is used upon termination in pendingDiskWG to ensure all writes have completed.
func (c *LocalCosigner) SaveLastSignedState(chainID string, signState types.SignStateConsensus) error {
	ccs, err := c.getChainState(chainID)
	if err != nil {
		return err
	}

	return ccs.lastSignState.Save(
		signState,
		&c.pendingDiskWG,
	)
}

// WaitForSignStatesToFlushToDisk waits for all state file writes queued
// in SaveLastSignedState to complete before termination.

func (c *LocalCosigner) waitForSignStatesToFlushToDisk() {
	c.pendingDiskWG.Wait()
}

func (c *LocalCosigner) WaitForSignStatesToFlushToDisk() {
	c.waitForSignStatesToFlushToDisk()
}

// GetID returns the id of the cosigner
// Implements Cosigner interface
func (c *LocalCosigner) GetID() int {
	return c.security.GetID()
}

// GetAddress returns the RPC URL of the cosigner
// Implements Cosigner interface
func (c *LocalCosigner) GetAddress() string {
	return c.address
}

func (c *LocalCosigner) getChainState(chainID string) (*ChainState, error) {
	cs, ok := c.chainStateMap.Load(chainID)
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
func (c *LocalCosigner) GetPubKey(chainID string) (cometcrypto.PubKey, error) {
	if err := c.LoadSignStateIfNecessary(chainID); err != nil {
		return nil, err
	}

	ccs, err := c.getChainState(chainID)
	if err != nil {
		return nil, err
	}

	return cometcryptoed25519.PubKey(ccs.signer.GetPubKey()), nil
}

// CombineSignatures combines partial signatures into a full signature.
func (c *LocalCosigner) CombineSignatures(chainID string, signatures []PartialSignature) ([]byte, error) {
	ccs, err := c.getChainState(chainID)
	if err != nil {
		return nil, err
	}

	return ccs.signer.CombineSignatures(signatures)
}

// VerifySignature validates a signed payload against the (persistent) public key.
// Implements Cosigner interface
func (c *LocalCosigner) VerifySignature(chainID string, payload, signature []byte) bool {
	if err := c.LoadSignStateIfNecessary(chainID); err != nil {
		return false
	}

	ccs, err := c.getChainState(chainID)
	if err != nil {
		return false
	}

	return cometcryptoed25519.PubKey(ccs.signer.GetPubKey()).VerifySignature(payload, signature)
}

// Sign the sign request using the cosigner's shard
// Return the signed bytes or an error
func (c *LocalCosigner) sign(req SignRequest) (SignResponse, error) {
	chainID := req.ChainID

	res := SignResponse{}

	ccs, err := c.getChainState(chainID)
	if err != nil {
		return res, err
	}

	// This function has multiple exit points.  Only start time can be guaranteed
	metrics.MetricsTimeKeeper.SetPreviousLocalSignStart(time.Now())

	hrst, err := types.UnpackHRST(req.SignBytes)
	if err != nil {
		return res, err
	}

	existingSignature, err := ccs.lastSignState.ExistingSignatureOrErrorIfRegression(hrst, req.SignBytes)
	if err != nil {
		return res, err
	}

	if existingSignature != nil {
		res.Signature = existingSignature
		return res, nil
	}

	nonces, err := ccs.combinedNonces(c.GetID(), uint8(c.Config.Config.ThresholdModeConfig.Threshold), hrst)
	if err != nil {
		return res, err
	}

	sig, err := ccs.signer.Sign(nonces, req.SignBytes)
	if err != nil {
		return res, err
	}

	err = ccs.lastSignState.Save(types.SignStateConsensus{
		Height:    hrst.Height,
		Round:     hrst.Round,
		Step:      hrst.Step,
		Signature: sig,
		SignBytes: req.SignBytes,
	}, &c.pendingDiskWG)

	if err != nil {
		if _, isSameHRSError := err.(*types.SameHRSError); !isSameHRSError {
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
	metrics.MetricsTimeKeeper.SetPreviousLocalSignFinish(time.Now())

	return res, nil
}

func (c *LocalCosigner) dealShares(req GetNonceRequest) ([]Nonces, error) {
	chainID := req.ChainID

	ccs, err := c.getChainState(chainID)
	if err != nil {
		return nil, err
	}

	meta := make([]Nonces, len(c.Config.Config.ThresholdModeConfig.Cosigners))

	nonces, err := ccs.signer.GenerateNonces()
	if err != nil {
		return nil, err
	}

	meta[c.GetID()-1] = nonces

	return meta, nil
}

func (c *LocalCosigner) LoadSignStateIfNecessary(chainID string) error {
	if chainID == "" {
		return fmt.Errorf("chain id cannot be empty")
	}

	if _, ok := c.chainStateMap.Load(chainID); ok {
		return nil
	}

	signState, err := types.LoadOrCreateSignState(c.Config.CosignStateFile(chainID))
	if err != nil {
		return err
	}

	var signer IThresholdSigner

	signer, err = NewThresholdSignerSoft(c.Config, c.GetID(), chainID)
	if err != nil {
		return err
	}

	c.chainStateMap.Store(chainID, &ChainState{
		lastSignState: signState,
		nonces:        make(map[types.HRSTKey][]Nonces),
		signer:        signer,
	})

	return nil
}

// GetNonces implements the ICosigner interface.
//
// GetNonces returns the nonces for the given HRS
func (c *LocalCosigner) GetNonces(
	chainID string,
	hrst types.HRSTKey,
) (*NoncesResponse, error) {
	metrics.MetricsTimeKeeper.SetPreviousLocalNonce(time.Now())

	if err := c.LoadSignStateIfNecessary(chainID); err != nil {
		return nil, err
	}

	total := len(c.Config.Config.ThresholdModeConfig.Cosigners)

	res := &NoncesResponse{
		Nonces: make([]WrappedNonce, total-1), // an empty list of nonces for each c except for ourselves
	}

	id := c.GetID()

	var eg errgroup.Group
	// getting nonces requires encrypting and signing for each cosigner,
	// so we perform these operations in parallel.

	for i := 0; i < total; i++ {
		peerID := i + 1
		if peerID == id {
			continue
		}

		i := i

		eg.Go(func() error {
			secretPart, err := c.getNonce(GetNonceRequest{
				ChainID:   chainID,
				ID:        peerID,
				Height:    hrst.Height,
				Round:     hrst.Round,
				Step:      hrst.Step,
				Timestamp: time.Unix(0, hrst.Timestamp),
			})

			if i >= id {
				res.Nonces[i-1] = secretPart
			} else {
				res.Nonces[i] = secretPart
			}

			return err
		})
	}

	if err := eg.Wait(); err != nil {
		return nil, err
	}

	c.logger.Debug(
		"Generated nonces",
		"chain_id", chainID,
		"height", hrst.Height,
		"round", hrst.Round,
		"step", hrst.Step,
	)

	return res, nil
}

func (c *LocalCosigner) dealSharesIfNecessary(chainID string, hrst types.HRSTKey) ([]Nonces, error) {
	ccs, err := c.getChainState(chainID)
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

	newNonces, err := c.dealShares(GetNonceRequest{
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
func (c *LocalCosigner) getNonce(
	req GetNonceRequest,
) (WrappedNonce, error) {

	chainID := req.ChainID
	zero := WrappedNonce{}
	hrst := types.HRSTKey{
		Height:    req.Height,
		Round:     req.Round,
		Step:      req.Step,
		Timestamp: req.Timestamp.UnixNano(),
	}

	id := c.GetID()

	meta, err := c.dealSharesIfNecessary(chainID, hrst)
	if err != nil {
		return zero, err
	}

	ourCosignerMeta := meta[id-1]
	nonce, err := c.security.EncryptAndSign(req.ID, ourCosignerMeta.PubKey, ourCosignerMeta.Shares[req.ID-1])
	if err != nil {
		return zero, err
	}

	return nonce, nil
}

// setNonce stores a nonce provided by another cosigner
func (c *LocalCosigner) setNonce(req SetNonceRequest) error {
	chainID := req.ChainID

	ccs, err := c.getChainState(chainID)
	if err != nil {
		return err
	}

	// Verify the source signature
	if req.Signature == nil {
		return errors.New("signature field is required")
	}

	noncePub, nonceShare, err := c.security.DecryptAndVerify(
		req.SourceID, req.PubKey, req.Share, req.Signature)
	if err != nil {
		return err
	}

	hrst := types.HRSTKey{
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
		nonces[req.SourceID-1].Shares = make([][]byte, len(c.Config.Config.ThresholdModeConfig.Cosigners))
	}
	nonces[req.SourceID-1].Shares[c.GetID()-1] = nonceShare
	nonces[req.SourceID-1].PubKey = noncePub

	return nil
}

func (c *LocalCosigner) SetNoncesAndSign(
	req SetNoncesAndSignRequest) (*SignResponse, error) {
	chainID := req.ChainID

	if err := c.LoadSignStateIfNecessary(chainID); err != nil {
		return nil, err
	}

	var eg errgroup.Group

	// setting nonces requires decrypting and verifying signature from each cosigner,
	// so we perform these operations in parallel.

	for _, secretPart := range req.Nonces {
		secretPart := secretPart

		eg.Go(func() error {
			return c.setNonce(SetNonceRequest{
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

	res, err := c.sign(SignRequest{
		ChainID:   chainID,
		SignBytes: req.SignBytes,
	})
	return &res, err
}
