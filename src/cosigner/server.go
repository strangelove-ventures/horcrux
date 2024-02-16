package cosigner

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/strangelove-ventures/horcrux/src/config"
	"github.com/strangelove-ventures/horcrux/src/metrics"
	"github.com/strangelove-ventures/horcrux/src/tss"
	"github.com/strangelove-ventures/horcrux/src/tss/tss25519"

	"github.com/strangelove-ventures/horcrux/src/types"

	cometcrypto "github.com/cometbft/cometbft/crypto"
	cometcryptoed25519 "github.com/cometbft/cometbft/crypto/ed25519"
	cometlog "github.com/cometbft/cometbft/libs/log"
	"github.com/google/uuid"
	"golang.org/x/sync/errgroup"
)

// var _ signer.ICosigner = &LocalCosigner{}

// double the CosignerNonceCache expiration so that sign requests from the leader
// never reference nonces which have expired here in the LocalCosigner.
const nonceExpiration = 20 * time.Second

const ErrUnexpectedState = "unexpected state, metadata does not exist for U:"

// LocalCosigner responds to sign requests.
// It maintains a high watermark to avoid double-signing.
// Signing is thread safe.
// TODO: Change name to CosignerServer
type LocalCosigner struct {
	logger        cometlog.Logger
	config        *config.RuntimeConfig
	security      ICosignerSecurity // TODO: Should be in a node above.
	chainState    sync.Map          // chainState is a map of chainID to *ChainState
	address       string
	pendingDiskWG sync.WaitGroup

	nonces map[uuid.UUID]*types.NoncesWithExpiration
	// protects the nonces map
	noncesMu sync.RWMutex

	// dealer generates nonces according to the "DKG" protocol
	dealer IThresholdDealer
}

// TODO: Change name to NewCosignerServer
func NewLocalCosigner(
	logger cometlog.Logger,
	config *config.RuntimeConfig,
	security ICosignerSecurity,
	address string,
) *LocalCosigner {
	return &LocalCosigner{
		logger:   logger,
		config:   config,
		security: security,
		address:  address,
		nonces:   make(map[uuid.UUID]*types.NoncesWithExpiration),
		dealer:   &tss25519.NonceGenerator{}, // TODO: Change to interface
	}
}

// FIX: Maybe name this something else and move the curve here as well.
type ChainState struct {
	// lastSignState stores the last sign state for an HRS we have fully signed
	// incremented whenever we are asked to sign an HRS
	lastSignState *types.SignState

	// signer, combines signatures, signs, and verifies signatures.
	signer IThresholdSigner

	// dealer generates nonces according to the "DKG" protocol
	// dealer IThresholdDealer
}

// StartNoncePruner periodically prunes nonces that have expired.
func (cosigner *LocalCosigner) StartNoncePruner(ctx context.Context) {
	ticker := time.NewTicker(nonceExpiration / 4)
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			cosigner.pruneNonces()
		}
	}
}

// pruneNonces removes nonces that have expired.
func (cosigner *LocalCosigner) pruneNonces() {
	cosigner.noncesMu.Lock()
	defer cosigner.noncesMu.Unlock()
	now := time.Now()
	for uuid, nonces := range cosigner.nonces {
		if now.After(nonces.Expiration) {
			delete(cosigner.nonces, uuid)
		}
	}
}

func (cosigner *LocalCosigner) combinedNonces(myID int, threshold uint8, uuid uuid.UUID) ([]types.Nonce, error) {
	cosigner.noncesMu.RLock()
	defer cosigner.noncesMu.RUnlock()

	nonces, ok := cosigner.nonces[uuid]
	if !ok {
		return nil, errors.New("no metadata at HRS")
	}

	combinedNonces := make([]types.Nonce, 0, threshold)

	// calculate secret and public keys
	for _, c := range nonces.Nonces {
		if len(c.Shares) == 0 || len(c.Shares[myID-1]) == 0 {
			continue
		}

		combinedNonces = append(combinedNonces, types.Nonce{
			Share:  c.Shares[myID-1],
			PubKey: c.PubKey,
		})
	}

	return combinedNonces, nil
}

// Save updates the high watermark height/round/step (HRS) if it is greater
// than the current high watermark. A mutex is used to avoid concurrent state updates.
// The disk write is scheduled in a separate goroutine which will perform an atomic write.
// pendingDiskWG is used upon termination in pendingDiskWG to ensure all writes have completed.
func (cosigner *LocalCosigner) SaveLastSignedState(chainID string, signState types.SignStateConsensus) error {
	ccs, err := cosigner.getChainState(chainID)
	if err != nil {
		return err
	}

	return ccs.lastSignState.Save(
		signState,
		&cosigner.pendingDiskWG,
	)
}

// WaitForSignStatesToFlushToDisk waits for all state file writes queued
// in SaveLastSignedState to complete before termination.
func (cosigner *LocalCosigner) WaitForSignStatesToFlushToDisk() {
	cosigner.pendingDiskWG.Wait()
}

// GetID returns the id of the cosigner
// Implements Cosigner interface
func (cosigner *LocalCosigner) GetIndex() int {
	return cosigner.security.GetID()
}

// GetAddress returns the RPC URL of the cosigner
// Implements Cosigner interface
func (cosigner *LocalCosigner) GetAddress() string {
	return cosigner.address
}

// TODO: Rename to fetchChainState
func (cosigner *LocalCosigner) getChainState(chainID string) (*ChainState, error) {
	cs, ok := cosigner.chainState.Load(chainID)
	if !ok {
		return nil, fmt.Errorf("failed to load chain state for %s", chainID)
	}

	// Asserting cs (type any) is actually of type *ChainState
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

	return cometcryptoed25519.PubKey(ccs.signer.GetPubKey()), nil
}

// CombineSignatures combines partial signatures into a full signature.
func (cosigner *LocalCosigner) CombineSignatures(chainID string, signatures []types.PartialSignature) ([]byte, error) {
	ccs, err := cosigner.getChainState(chainID)
	if err != nil {
		return nil, err
	}

	return ccs.signer.CombineSignatures(signatures)
}

// VerifySignature validates a signed payload against the public key.
// Implements Cosigner interface Should not be part of Cosigner.
// Should be part of a higher level interface.
func (cosigner *LocalCosigner) VerifySignature(chainID string, payload, signature []byte) bool {
	if err := cosigner.LoadSignStateIfNecessary(chainID); err != nil {
		return false
	}

	ccs, err := cosigner.getChainState(chainID)
	if err != nil {
		return false
	}

	sig := make([]byte, len(signature))
	copy(sig, signature)

	return cometcryptoed25519.PubKey(ccs.signer.GetPubKey()).VerifySignature(payload, sig)
}

// Sign the sign request using the cosigner's shard
// Return the signed bytes or an error
// Implements Cosigner interface
func (cosigner *LocalCosigner) sign(req SignatureRequest) (SignatureResponse, error) {
	chainID := req.ChainID

	res := SignatureResponse{}

	ccs, err := cosigner.getChainState(chainID)
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

	nonces, err := cosigner.combinedNonces(
		cosigner.GetIndex(),
		uint8(cosigner.config.Config.ThresholdModeConfig.Threshold),
		req.UUID,
	)
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
	}, &cosigner.pendingDiskWG)

	if err != nil {
		var sameHRSError *types.SameHRSError
		if !errors.As(err, &sameHRSError) {
			return res, err
		}
	}

	cosigner.noncesMu.Lock()
	delete(cosigner.nonces, req.UUID)
	cosigner.noncesMu.Unlock()

	res.Signature = sig

	// Note - Function may return before this line so elapsed time for Finish may be multiple block times
	metrics.MetricsTimeKeeper.SetPreviousLocalSignFinish(time.Now())

	return res, nil
}

func (cosigner *LocalCosigner) generateNonces() ([]types.Nonces, error) {
	total := len(cosigner.config.Config.ThresholdModeConfig.Cosigners)
	meta := make([]types.Nonces, total)

	// TODO: This should only generate nonces for the cosigners that are online
	// 		 although it might doesnt matter if we arent doing DKG
	// Should call an interface: dealnonce or something
	threshold := uint8(cosigner.config.Config.ThresholdModeConfig.Threshold)
	nonces, err := cosigner.dealer.GenerateNonces(uint8(threshold), uint8(total))
	if err != nil {
		fmt.Println("Error is: ", err)
		return nil, err
	}

	meta[cosigner.GetIndex()-1] = nonces

	return meta, nil
}

func (cosigner *LocalCosigner) LoadSignStateIfNecessary(chainID string) error {
	if chainID == "" {
		return fmt.Errorf("chain id cannot be empty")
	}

	if _, ok := cosigner.chainState.Load(chainID); ok {
		return nil
	}

	signState, err := types.LoadOrCreateSignState(cosigner.config.CosignerStateFile(chainID))
	if err != nil {
		return err
	}

	var signer IThresholdSigner
	signer, err = tss.NewThresholdEd25519SignerSoft(cosigner.config, cosigner.GetIndex(), chainID)
	if err != nil {
		return err
	}

	cosigner.chainState.Store(chainID, &ChainState{
		lastSignState: signState,
		signer:        signer,
	})

	return nil
}

// GetNonces returns the nonces for the given UUIDs, generating if necessary.
func (cosigner *LocalCosigner) GetNonces(
	_ context.Context,
	uuids []uuid.UUID,
) (CosignerUUIDNoncesMultiple, error) {
	metrics.MetricsTimeKeeper.SetPreviousLocalNonce(time.Now())

	total := len(cosigner.config.Config.ThresholdModeConfig.Cosigners)

	res := make(CosignerUUIDNoncesMultiple, len(uuids))

	id := cosigner.GetIndex()

	var outerEg errgroup.Group
	// getting nonces requires encrypting and signing for each cosigner,
	// so we perform these operations in parallel.

	for j, u := range uuids {
		j := j
		u := u

		outerEg.Go(func() error {
			meta, err := cosigner.generateNoncesIfNecessary(u)
			if err != nil {
				return err
			}

			var eg errgroup.Group

			nonces := make([]Nonce, total-1)

			for i := 0; i < total; i++ {
				peerID := i + 1
				if peerID == id {
					continue
				}

				i := i

				eg.Go(func() error {
					secretPart, err := cosigner.getNonce(meta, peerID)

					if i >= id {
						nonces[i-1] = secretPart
					} else {
						nonces[i] = secretPart
					}

					return err
				})
			}

			if err := eg.Wait(); err != nil {
				return err
			}

			res[j] = &CosignerUUIDNonces{
				UUID:   u,
				Nonces: nonces,
			}

			return nil
		})
	}

	if err := outerEg.Wait(); err != nil {
		return nil, err
	}

	return res, nil
}

func (cosigner *LocalCosigner) generateNoncesIfNecessary(uuid uuid.UUID) (*types.NoncesWithExpiration, error) {
	// protects the meta map
	cosigner.noncesMu.RLock()
	nonces, ok := cosigner.nonces[uuid]
	cosigner.noncesMu.RUnlock()
	if ok {
		return nonces, nil
	}

	newNonces, err := cosigner.generateNonces()
	if err != nil {
		fmt.Println(err)
		return nil, err
	}

	res := types.NoncesWithExpiration{
		Nonces:     newNonces,
		Expiration: time.Now().Add(nonceExpiration),
	}

	cosigner.noncesMu.Lock()
	cosigner.nonces[uuid] = &res
	cosigner.noncesMu.Unlock()

	return &res, nil
}

// Get the ephemeral secret part for an ephemeral share
// The ephemeral secret part is encrypted for the receiver
func (cosigner *LocalCosigner) getNonce(
	meta *types.NoncesWithExpiration,
	peerID int,
) (Nonce, error) {
	zero := Nonce{}

	id := cosigner.GetIndex()

	ourCosignerMeta := meta.Nonces[id-1]
	nonce, err := cosigner.security.EncryptAndSign(peerID, ourCosignerMeta.PubKey, ourCosignerMeta.Shares[peerID-1])
	if err != nil {
		return zero, err
	}

	return nonce, nil
}

// setNonce stores a nonce provided by another cosigner
func (cosigner *LocalCosigner) setNonce(uuid uuid.UUID, nonce Nonce) error {
	// Verify the source signature
	if nonce.Signature == nil {
		return errors.New("signature field is required")
	}

	noncePub, nonceShare, err := cosigner.security.DecryptAndVerify(
		nonce.SourceID, nonce.PubKey, nonce.Share, nonce.Signature)
	if err != nil {
		return err
	}

	// protects the meta map
	cosigner.noncesMu.Lock()
	defer cosigner.noncesMu.Unlock()

	n, ok := cosigner.nonces[uuid]
	// generate metadata placeholder
	if !ok {
		return fmt.Errorf(
			"%s %s",
			ErrUnexpectedState,
			uuid,
		)
	}

	// set slot
	if n.Nonces[nonce.SourceID-1].Shares == nil {
		n.Nonces[nonce.SourceID-1].Shares = make([][]byte, len(cosigner.config.Config.ThresholdModeConfig.Cosigners))
	}
	n.Nonces[nonce.SourceID-1].Shares[cosigner.GetIndex()-1] = nonceShare
	n.Nonces[nonce.SourceID-1].PubKey = noncePub

	return nil
}

func (cosigner *LocalCosigner) SetNoncesAndSign(
	_ context.Context,
	req CosignerSetNoncesAndSignRequest) (*SignatureResponse, error) {
	chainID := req.ChainID

	if err := cosigner.LoadSignStateIfNecessary(chainID); err != nil {
		return nil, err
	}

	var eg errgroup.Group

	// setting nonces requires decrypting and verifying signature from each cosigner,
	// so we perform these operations in parallel.

	for _, secretPart := range req.Nonces.Nonces {
		secretPart := secretPart

		eg.Go(func() error {
			return cosigner.setNonce(req.Nonces.UUID, secretPart)
		})
	}

	if err := eg.Wait(); err != nil {
		return nil, err
	}

	res, err := cosigner.sign(SignatureRequest{
		UUID:      req.Nonces.UUID,
		ChainID:   chainID,
		SignBytes: req.SignBytes,
	})
	return &res, err
}
