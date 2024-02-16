package node_test

import (
	"bytes"
	"context"
	"crypto/rand"
	"fmt"
	"path/filepath"
	"time"

	"github.com/strangelove-ventures/horcrux/src/config"
	"github.com/strangelove-ventures/horcrux/src/connector"
	"github.com/strangelove-ventures/horcrux/src/cosigner"
	"github.com/strangelove-ventures/horcrux/src/cosigner/nodesecurity"
	"github.com/strangelove-ventures/horcrux/src/node"
	"github.com/strangelove-ventures/horcrux/src/tss"

	"github.com/strangelove-ventures/horcrux/src/types"

	"os"
	"testing"

	cometcrypto "github.com/cometbft/cometbft/crypto"
	cometcryptoed25519 "github.com/cometbft/cometbft/crypto/ed25519"
	"github.com/cometbft/cometbft/crypto/tmhash"
	"github.com/cometbft/cometbft/libs/log"
	cometrand "github.com/cometbft/cometbft/libs/rand"
	cometproto "github.com/cometbft/cometbft/proto/tendermint/types"
	"github.com/ethereum/go-ethereum/crypto/ecies"
	"github.com/ethereum/go-ethereum/crypto/secp256k1"
	"github.com/stretchr/testify/require"
	ted25519 "gitlab.com/unit410/threshold-ed25519/pkg"
	"golang.org/x/sync/errgroup"
)

var (
	testConfig *config.RuntimeConfig // use this global config in tests

)
var _ connector.IPrivValidator = &node.ThresholdValidator{}

const (
	defaultGetNoncesInterval = 3 * time.Second
	defaultGetNoncesTimeout  = 4 * time.Second
	defaultNonceExpiration   = 10 * time.Second // half of the local cosigner cache expiration

)

type MockValidator struct {
	*node.ThresholdValidator
	nonceCache *node.CosignerNonceCache
	// cosignerHealth *node.CosignerHealth
}

func NewMockValidator(
	logger log.Logger,
	config *config.RuntimeConfig,
	threshold int,
	grpcTimeout time.Duration,
	maxWaitForSameBlockAttempts int,
	myCosigner *cosigner.LocalCosigner,
	peerCosigners []node.ICosigner,
	leader node.ILeader,
) *MockValidator {
	allCosigners := make([]node.ICosigner, len(peerCosigners)+1)
	allCosigners[0] = myCosigner
	copy(allCosigners[1:], peerCosigners)

	for _, peer := range peerCosigners {
		logger.Debug("Peer peer", "id", peer.GetIndex())
	}

	nc := node.NewCosignerNonceCache(
		logger,
		allCosigners,
		leader,
		defaultGetNoncesInterval,
		defaultGetNoncesTimeout,
		defaultNonceExpiration,
		uint8(threshold),
		nil,
	)
	// nch := node.NewCosignerHealth(logger, peerCosigners, leader)
	return &MockValidator{
		node.NewThresholdValidator(logger, config, threshold, grpcTimeout, maxWaitForSameBlockAttempts,
			allCosigners[0].(*cosigner.LocalCosigner), peerCosigners[1:], leader), nc,
	}
}

func TestMain(m *testing.M) {
	// optional alternative config via ENV VAR `CONFIG`
	// if path := os.Getenv("CONFIG"); path != "" {

	//     conf, err := LoadConfig(path)
	//     if err != nil {
	//         log.Fatalf("Failed to load config file %q : %v", path, err)
	//     }

	//     testConfig = &conf

	// } else {
	//     testConfig = &config.RuntimeConfig{}
	// }
	testConfig = &config.RuntimeConfig{}
	// call flag.Parse() here if TestMain uses flags
	os.Exit(m.Run())
}
func TestThresholdValidator2of2(t *testing.T) {
	testThresholdValidator(t, 2, 2, testConfig)
}

func TestThresholdValidator3of3(t *testing.T) {
	testThresholdValidator(t, 3, 3, testConfig)
}

func TestThresholdValidator2of3(t *testing.T) {
	testThresholdValidator(t, 2, 3, testConfig)
}

func TestThresholdValidator3of5(t *testing.T) {
	testThresholdValidator(t, 3, 5, testConfig)
}

func loadKeyForLocalCosigner(
	cosigner *cosigner.LocalCosigner,
	pubKey cometcrypto.PubKey,
	chainID string,
	privateShard []byte,
	config *config.RuntimeConfig,
) error {
	key := tss.Ed25519Key{
		PubKey:       pubKey,
		PrivateShard: privateShard,
		ID:           cosigner.GetIndex(),
	}

	keyBz, err := key.MarshalJSON()
	if err != nil {
		return err
	}

	return os.WriteFile(config.KeyFilePathCosigner(chainID), keyBz, 0600)
}
func testThresholdValidator(t *testing.T, threshold, total uint8, configuration *config.RuntimeConfig) {
	cosigners, pubKey := getTestLocalCosigners(t, threshold, total)

	fmt.Println("cosigners", threshold, total, len(cosigners))

	thresholdCosigners := make([]node.ICosigner, 0, threshold-1)
	fmt.Println("thresholdCosigners", threshold, total, len(thresholdCosigners))

	for i, cosigner := range cosigners {
		require.Equal(t, i+1, cosigner.GetIndex())

		if i != 0 && len(thresholdCosigners) != int(threshold)-1 {
			thresholdCosigners = append(thresholdCosigners, cosigner)
		}
	}

	leader := &MockLeader{id: 1}

	validator := NewMockValidator(
		log.NewNopLogger(),
		configuration,
		int(threshold),
		time.Second,
		1,
		cosigners[0],
		thresholdCosigners,
		leader,
	)
	defer validator.Stop()

	// var mockvalidator *MockValidator
	// mockvalidator = mockvalidator(validator)

	leader.leader = validator.ThresholdValidator

	ctx := context.Background()

	err := validator.LoadSignStateIfNecessary(testChainID)
	require.NoError(t, err)

	proposal := cometproto.Proposal{
		Height: 1,
		Round:  20,
		Type:   cometproto.ProposalType,
	}

	block := types.ProposalToBlock(testChainID, &proposal)
	signature, _, err := validator.Sign(ctx, testChainID, block)
	require.NoError(t, err)

	require.True(t, pubKey.VerifySignature(block.SignBytes, signature))

	firstSignature := signature

	require.Len(t, firstSignature, 64)

	proposal = cometproto.Proposal{
		Height:    1,
		Round:     20,
		Type:      cometproto.ProposalType,
		Timestamp: time.Now(),
	}

	block = types.ProposalToBlock(testChainID, &proposal)

	validator.nonceCache.LoadN(ctx, 1)

	// should be able to sign same proposal with only differing timestamp
	_, _, err = validator.Sign(ctx, testChainID, block)
	require.NoError(t, err)

	// construct different block Index for proposal at same height as highest signed
	randHash := cometrand.Bytes(tmhash.Size)
	blockID := cometproto.BlockID{Hash: randHash,
		PartSetHeader: cometproto.PartSetHeader{Total: 5, Hash: randHash}}

	proposal = cometproto.Proposal{
		Height:  1,
		Round:   20,
		Type:    cometproto.ProposalType,
		BlockID: blockID,
	}

	validator.nonceCache.LoadN(ctx, 1)

	// different than single-signer mode, threshold mode will be successful for this,
	// but it will return the same signature as before.
	signature, _, err = validator.Sign(ctx, testChainID, types.ProposalToBlock(testChainID, &proposal))
	require.NoError(t, err)

	require.True(t, bytes.Equal(firstSignature, signature))

	proposal.Round = 19

	validator.nonceCache.LoadN(ctx, 1)

	// should not be able to sign lower than highest signed
	_, _, err = validator.Sign(ctx, testChainID, types.ProposalToBlock(testChainID, &proposal))
	require.Error(t, err, "double sign!")

	validator.nonceCache.LoadN(ctx, 1)

	// lower LSS should sign for different chain Index
	_, _, err = validator.Sign(ctx, testChainID2, types.ProposalToBlock(testChainID2, &proposal))
	require.NoError(t, err)

	// reinitialize validator to make sure new runtime will not allow double sign
	newValidator := NewMockValidator(
		log.NewNopLogger(),
		configuration,
		int(threshold),
		time.Second,
		1,
		cosigners[0],
		thresholdCosigners,
		leader,
	)
	defer newValidator.Stop()

	newValidator.nonceCache.LoadN(ctx, 1)

	_, _, err = newValidator.Sign(ctx, testChainID, types.ProposalToBlock(testChainID, &proposal))
	require.Error(t, err, "double sign!")

	proposal = cometproto.Proposal{
		Height:    1,
		Round:     21,
		Type:      cometproto.ProposalType,
		Timestamp: time.Now(),
	}

	proposalClone := proposal
	proposalClone.Timestamp = proposal.Timestamp.Add(2 * time.Millisecond)

	proposalClone2 := proposal
	proposalClone2.Timestamp = proposal.Timestamp.Add(4 * time.Millisecond)

	var eg errgroup.Group

	newValidator.nonceCache.LoadN(ctx, 3)

	eg.Go(func() error {
		_, _, err := newValidator.Sign(ctx, testChainID, types.ProposalToBlock(testChainID, &proposal))
		return err
	})
	eg.Go(func() error {
		_, _, err := newValidator.Sign(ctx, testChainID, types.ProposalToBlock(testChainID, &proposalClone))
		return err
	})
	eg.Go(func() error {
		_, _, err := newValidator.Sign(ctx, testChainID, types.ProposalToBlock(testChainID, &proposalClone2))
		return err
	})
	// signing higher block now should succeed
	err = eg.Wait()
	require.NoError(t, err)

	// Sign some votes from multiple sentries
	for i := 2; i < 50; i++ {
		newValidator.nonceCache.LoadN(ctx, 3)

		prevote := cometproto.Vote{
			Height:    int64(i),
			Round:     0,
			Type:      cometproto.PrevoteType,
			Timestamp: time.Now(),
		}

		prevoteClone := prevote
		prevoteClone.Timestamp = prevote.Timestamp.Add(2 * time.Millisecond)

		prevoteClone2 := prevote
		prevoteClone2.Timestamp = prevote.Timestamp.Add(4 * time.Millisecond)

		eg.Go(func() error {
			start := time.Now()
			_, _, err := newValidator.Sign(ctx, testChainID, types.VoteToBlock(testChainID, &prevote))
			t.Log("Sign time", "duration", time.Since(start))
			return err
		})
		eg.Go(func() error {
			start := time.Now()
			_, _, err := newValidator.Sign(ctx, testChainID, types.VoteToBlock(testChainID, &prevoteClone))
			t.Log("Sign time", "duration", time.Since(start))
			return err
		})
		eg.Go(func() error {
			start := time.Now()
			_, _, err := newValidator.Sign(ctx, testChainID, types.VoteToBlock(testChainID, &prevoteClone2))
			t.Log("Sign time", "duration", time.Since(start))
			return err
		})

		err = eg.Wait()
		require.NoError(t, err)

		precommit := cometproto.Vote{
			Height:    int64(i),
			Round:     0,
			Type:      cometproto.PrecommitType,
			Timestamp: time.Now(),
		}

		precommitClone := precommit
		precommitClone.Timestamp = precommit.Timestamp.Add(2 * time.Millisecond)

		precommitClone2 := precommit
		precommitClone2.Timestamp = precommit.Timestamp.Add(4 * time.Millisecond)

		newValidator.nonceCache.LoadN(ctx, 3)

		eg.Go(func() error {
			start := time.Now()
			t.Log("Sign time", "duration", time.Since(start))
			_, _, err := newValidator.Sign(ctx, testChainID, types.VoteToBlock(testChainID, &precommit))
			return err
		})
		eg.Go(func() error {
			start := time.Now()
			t.Log("Sign time", "duration", time.Since(start))
			_, _, err := newValidator.Sign(ctx, testChainID, types.VoteToBlock(testChainID, &precommitClone))
			return err
		})
		eg.Go(func() error {
			start := time.Now()
			_, _, err := newValidator.Sign(ctx, testChainID, types.VoteToBlock(testChainID, &precommitClone2))
			t.Log("Sign time", "duration", time.Since(start))
			return err
		})

		err = eg.Wait()
		require.NoError(t, err)
	}
}

func getTestLocalCosigners(t *testing.T, threshold, total uint8) ([]*cosigner.LocalCosigner, cometcrypto.PubKey) {
	eciesKeys := make([]*ecies.PrivateKey, total)
	pubKeys := make([]*ecies.PublicKey, total)
	cosigners := make([]*cosigner.LocalCosigner, total)

	for i := uint8(0); i < total; i++ {
		eciesKey, err := ecies.GenerateKey(rand.Reader, secp256k1.S256(), nil)
		require.NoError(t, err)

		eciesKeys[i] = eciesKey

		pubKeys[i] = &eciesKey.PublicKey
	}

	privateKey := cometcryptoed25519.GenPrivKey()
	privKeyBytes := privateKey[:]
	privShards := ted25519.DealShares(ted25519.ExpandSecret(privKeyBytes[:32]), threshold, total)

	tmpDir := t.TempDir()

	cosignersConfig := make(config.CosignersConfig, total)

	for i := range pubKeys {
		cosignersConfig[i] = config.CosignerConfig{
			ShardID: i + 1,
		}
	}

	for i := range pubKeys {
		cosignerDir := filepath.Join(tmpDir, fmt.Sprintf("cosigner_%d", i+1))
		err := os.MkdirAll(cosignerDir, 0777)
		require.NoError(t, err)

		cosignerConfig := &config.RuntimeConfig{
			HomeDir:  cosignerDir,
			StateDir: cosignerDir,
			Config: config.Config{
				ThresholdModeConfig: &config.ThresholdModeConfig{
					Threshold: int(threshold),
					Cosigners: cosignersConfig,
				},
			},
		}

		cosigner := cosigner.NewLocalCosigner(
			log.NewNopLogger(),
			cosignerConfig,
			nodesecurity.NewCosignerSecurityECIES(
				nodesecurity.CosignerECIESKey{
					ID:        i + 1,
					ECIESKey:  eciesKeys[i],
					ECIESPubs: pubKeys,
				},
			),
			"",
		)
		require.NoError(t, err)

		cosigners[i] = cosigner

		err = loadKeyForLocalCosigner(cosigner, privateKey.PubKey(), testChainID, privShards[i], cosignerConfig)
		require.NoError(t, err)

		err = loadKeyForLocalCosigner(cosigner, privateKey.PubKey(), testChainID2, privShards[i], cosignerConfig)
		require.NoError(t, err)
	}

	return cosigners, privateKey.PubKey()
}

/*
func testThresholdValidatorLeaderElection(t *testing.T, threshold, total uint8) {
	peers, pubKey := getTestLocalCosigners(t, threshold, total)

	thresholdValidators := make([]*MockThresholdValidator, 0, total)
	var leader *signer.ThresholdValidator
	leaders := make([]*MockLeader, total)

	ctx := context.Background()

	for i, peer := range peers {
		peers := make([]signer.ICosigner, 0, len(peers)-1)
		for j, otherCosigner := range peers {
			if i != j {
				peers = append(peers, otherCosigner)
			}
		}
		leaders[i] = &MockLeader{id: peer.GetIndex(), leader: leader}
		tv := NewMockValidator(
			cometlog.NewNopLogger(),
			peer.config,
			int(threshold),
			time.Second,
			1,
			peer,
			peers,
			leaders[i],
		)
		if i == 0 {
			leader = tv.ThresholdValidator
			leaders[i].leader = tv.ThresholdValidator
		}

		thresholdValidators = append(thresholdValidators, tv.ThresholdValidator)
		defer tv.Stop()

		err := tv.LoadSignStateIfNecessary(testChainID)
		require.NoError(t, err)

		require.NoError(t, tv.Start(ctx))
	}

	quit := make(chan bool)
	done := make(chan bool)

	go func() {
		for i := 0; true; i++ {
			select {
			case <-quit:
				done <- true
				return
			default:
			}
			// simulate leader election
			for _, l := range leaders {
				l.SetLeader(nil)
			}
			t.Log("No leader")

			// time without a leader
			time.Sleep(time.Duration(mrand.Intn(50)+100) * time.Millisecond) //nolint:gosec

			newLeader := thresholdValidators[i%len(thresholdValidators)]
			for _, l := range leaders {
				l.SetLeader(newLeader)
			}
			t.Logf("New leader: %d", newLeader.MyCosigner.GetIndex())

			// time with new leader
			time.Sleep(time.Duration(mrand.Intn(50)+100) * time.Millisecond) //nolint:gosec
		}
	}()

	// sign 20 blocks (proposal, prevote, precommit)
	for i := 0; i < 20; i++ {
		var wg sync.WaitGroup
		wg.Add(len(thresholdValidators))
		var mu sync.Mutex
		success := false
		for _, tv := range thresholdValidators {
			tv := tv

			tv.nonceCache.LoadN(ctx, 1)

			go func() {
				defer wg.Done()
				// stagger signing requests with random sleep
				time.Sleep(time.Duration(mrand.Intn(50)+100) * time.Millisecond) //nolint:gosec

				proposal := cometproto.Proposal{
					Height: 1 + int64(i),
					Round:  1,
					Type:   cometproto.ProposalType,
				}

				signature, _, err := tv.Sign(ctx, testChainID, types.ProposalToBlock(testChainID, &proposal))
				if err != nil {
					t.Log("Proposal sign failed", "error", err)
					return
				}

				signBytes := comet.ProposalSignBytes(testChainID, &proposal)

				sig := make([]byte, len(signature))
				copy(sig, signature)

				if !pubKey.VerifySignature(signBytes, sig) {
					t.Log("Proposal signature verification failed")
					return
				}

				mu.Lock()
				defer mu.Unlock()
				success = true
			}()
		}

		wg.Wait()
		require.True(t, success) // at least one should succeed so that the block is not missed.
		wg.Add(len(thresholdValidators))
		success = false
		for _, tv := range thresholdValidators {
			tv := tv

			tv.nonceCache.LoadN(ctx, 1)

			go func() {
				defer wg.Done()
				// stagger signing requests with random sleep
				time.Sleep(time.Duration(mrand.Intn(50)+100) * time.Millisecond) //nolint:gosec

				preVote := cometproto.Vote{
					Height: 1 + int64(i),
					Round:  1,
					Type:   cometproto.PrevoteType,
				}

				signature, _, err := tv.Sign(ctx, testChainID, types.VoteToBlock(testChainID, &preVote))
				if err != nil {
					t.Log("PreVote sign failed", "error", err)
					return
				}

				signBytes := comet.VoteSignBytes(testChainID, &preVote)

				sig := make([]byte, len(signature))
				copy(sig, signature)

				if !pubKey.VerifySignature(signBytes, sig) {
					t.Log("PreVote signature verification failed")
					return
				}

				mu.Lock()
				defer mu.Unlock()
				success = true
			}()
		}

		wg.Wait()
		require.True(t, success) // at least one should succeed so that the block is not missed.
		wg.Add(len(thresholdValidators))
		success = false
		for _, tv := range thresholdValidators {
			tv := tv

			tv.nonceCache.LoadN(ctx, 1)

			go func() {
				defer wg.Done()
				// stagger signing requests with random sleep
				time.Sleep(time.Duration(mrand.Intn(50)+100) * time.Millisecond) //nolint:gosec

				preCommit := cometproto.Vote{
					Height: 1 + int64(i),
					Round:  1,
					Type:   cometproto.PrecommitType,
				}

				signature, _, err := tv.Sign(ctx, testChainID, types.VoteToBlock(testChainID, &preCommit))
				if err != nil {
					t.Log("PreCommit sign failed", "error", err)
					return
				}

				signBytes := comet.VoteSignBytes(testChainID, &preCommit)

				sig := make([]byte, len(signature))
				copy(sig, signature)

				if !pubKey.VerifySignature(signBytes, sig) {
					t.Log("PreCommit signature verification failed")
					return
				}

				mu.Lock()
				defer mu.Unlock()
				success = true
			}()
		}

		wg.Wait()

		require.True(t, success) // at least one should succeed so that the block is not missed.
	}

	quit <- true
	<-done
}

func TestThresholdValidatorLeaderElection2of3(t *testing.T) {
	testThresholdValidatorLeaderElection(t, 2, 3)
}
*/
