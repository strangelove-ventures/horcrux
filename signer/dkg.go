package signer

import (
	"context"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"math/rand"
	"sync"
	"time"

	"github.com/avast/retry-go/v4"
	cometcryptoed25519 "github.com/cometbft/cometbft/crypto/ed25519"
	"github.com/libp2p/go-libp2p"
	pubsub "github.com/libp2p/go-libp2p-pubsub"
	"github.com/libp2p/go-libp2p/core/crypto"
	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/strangelove-ventures/horcrux/signer/keygen"
)

var (
	topicDKG = "dkg"
)

type RoundMessages struct {
	Round    uint8    `json:"round"`
	ID       uint8    `json:"id"`
	Messages [][]byte `json:"messages"`
}

func NetworkDKG(
	ctx context.Context,
	cosigners CosignersConfig,
	id uint8,
	rsaKeys CosignerRSAKey,
	threshold uint8,
) (*CosignerEd25519Key, error) {
	cosigner, err := cosigners.MyCosigner(id)
	if err != nil {
		return nil, err
	}

	hostAddr, err := cosigner.LibP2PHostAddr()
	if err != nil {
		return nil, err
	}

	x509Bz := x509.MarshalPKCS1PrivateKey(&rsaKeys.RSAKey)

	p2pPrivateKey, err := crypto.UnmarshalRsaPrivateKey(x509Bz)
	if err != nil {
		return nil, err
	}

	h, err := libp2p.New(libp2p.ListenAddrStrings(hostAddr), libp2p.Identity(p2pPrivateKey))
	if err != nil {
		return nil, fmt.Errorf("failed to construct libp2p node: %w", err)
	}

	defer h.Close()

	ps, err := pubsub.NewGossipSub(ctx, h)
	if err != nil {
		return nil, fmt.Errorf("failed to setup libp2p pub sub: %w", err)
	}

	total := len(cosigners)

	keygenCosigner, err := keygen.NewCosigner(id, threshold, uint8(total))
	if err != nil {
		return nil, err
	}

	dkgTopic, err := ps.Join(topicDKG)
	if err != nil {
		return nil, fmt.Errorf("failed to join topic: %w", err)
	}

	sub, err := dkgTopic.Subscribe()
	if err != nil {
		return nil, fmt.Errorf("failed to subscribe to topic: %w", err)
	}

	fmt.Println("Starting cosigner discovery")

	if err := waitForAllCosigners(ctx, h, id, cosigners.OtherCosigners(id), rsaKeys.RSAPubs); err != nil {
		return nil, err
	}

	fmt.Println("Cosigner discovery complete")

	if err := processRounds(ctx, dkgTopic, sub, keygenCosigner, uint8(total)); err != nil {
		return nil, err
	}

	return &CosignerEd25519Key{
		PubKey:       cometcryptoed25519.PubKey(keygenCosigner.Public().GroupKey.ToEd25519()),
		PrivateShard: keygenCosigner.Secret().Secret.Bytes(),
		ID:           id,
	}, nil
}

func publishUntilRoundDone(
	ctx context.Context,
	topic *pubsub.Topic,
	msg []byte,
	doneCh chan struct{},
) {
	for {
		nextPublish := rand.Intn(1000) + 2000 //nolint
		select {
		case <-ctx.Done():
			return
		case <-doneCh:
			return
		case <-time.After(time.Duration(nextPublish) * time.Millisecond):
			if err := topic.Publish(ctx, msg); err != nil {
				fmt.Printf("Failed to publish msg to topic: %v\n", err)
			}
		}
	}
}

func processRounds(
	ctx context.Context,
	dkgTopic *pubsub.Topic,
	sub *pubsub.Subscription,
	keygenCosigner keygen.Cosigner,
	total uint8,
) error {
	id := uint8(keygenCosigner.ID)

	allRound1Msgs := make([][]byte, total)
	allRound2Msgs := make([][]byte, total*(total-1))
	allRound3Msgs := make([][]byte, total)

	round1DoneCh := make(chan struct{}, 1)
	round2DoneCh := make(chan struct{}, 1)
	round3DoneCh := make(chan struct{}, 1)

	round1, err := keygenCosigner.Round1()
	if err != nil {
		return err
	}

	round1Msgs := RoundMessages{
		Round:    1,
		ID:       id,
		Messages: round1,
	}

	round1MsgsBz, err := json.Marshal(round1Msgs)
	if err != nil {
		return err
	}

	go publishUntilRoundDone(ctx, dkgTopic, round1MsgsBz, round1DoneCh)

RecvRoundMsgsLoop:
	for {
		m, err := sub.Next(ctx)
		if err != nil {
			fmt.Printf("Failed to retrieve next message from topic subscription: %v\n", err)
			continue RecvRoundMsgsLoop
		}
		fmt.Printf("Received data on cosigner %d - %s\n", id, string(m.Message.Data))

		var cosignerRoundMsgs RoundMessages
		if err := json.Unmarshal(m.Message.Data, &cosignerRoundMsgs); err != nil {
			fmt.Printf("Failed to unmarshal message from topic subscription: %v\n", err)
			continue RecvRoundMsgsLoop
		}
		cID := cosignerRoundMsgs.ID

		switch cosignerRoundMsgs.Round {
		case 1:
			allRound1Msgs[cID-1] = cosignerRoundMsgs.Messages[0]

			shouldContinue := false
			for i, m := range allRound1Msgs {
				if len(m) == 0 {
					fmt.Printf("Still waiting on msgs for round 1 on cosigner %d from cosigner %d\n", id, i+1)
					shouldContinue = true
				}
			}

			if shouldContinue {
				continue RecvRoundMsgsLoop
			}

			round1DoneCh <- struct{}{}

			// have messages from all cosigners for round 1
			round2, err := keygenCosigner.Round2(allRound1Msgs)
			if err != nil {
				return err
			}

			round2Msgs := RoundMessages{
				Round:    2,
				ID:       id,
				Messages: round2,
			}

			round2MsgsBz, err := json.Marshal(round2Msgs)
			if err != nil {
				return err
			}

			go publishUntilRoundDone(ctx, dkgTopic, round2MsgsBz, round2DoneCh)

		case 2:
			copy(allRound2Msgs[(cID-1)*(total-1):cID*(total-1)], cosignerRoundMsgs.Messages)

			shouldContinue := false
			for i, m := range allRound2Msgs {
				if len(m) == 0 {
					fmt.Printf("Still waiting on msgs for round 2 on cosigner %d from cosigner %d\n", id, i+1)
					shouldContinue = true
				}
			}

			if shouldContinue {
				continue RecvRoundMsgsLoop
			}

			round2DoneCh <- struct{}{}

			// have messages from all cosigners for round 2
			if err := keygenCosigner.Round3(allRound2Msgs); err != nil {
				return err
			}

			if err := keygenCosigner.WaitForCompletion(); err != nil {
				return err
			}

			round3Msgs := RoundMessages{
				Round: 3,
				ID:    id,
			}

			round3MsgsBz, err := json.Marshal(round3Msgs)
			if err != nil {
				return err
			}

			go publishUntilRoundDone(ctx, dkgTopic, round3MsgsBz, round3DoneCh)
		case 3:
			allRound3Msgs[cID-1] = []byte{0x01}

			shouldContinue := false
			for i, m := range allRound3Msgs {
				if len(m) == 0 {
					fmt.Printf("Still waiting on msgs for round 3 on cosigner %d from cosigner %d\n", id, i+1)
					shouldContinue = true
				}
			}

			if shouldContinue {
				continue RecvRoundMsgsLoop
			}

			round3DoneCh <- struct{}{}

			// have success from all cosigners, sharding complete
			return nil
		default:
			fmt.Printf("Unexpected round: %d\n", cosignerRoundMsgs.Round)
		}
	}
}

func waitForAllCosigners(
	ctx context.Context,
	h host.Host,
	id uint8,
	cosigners CosignersConfig,
	rsaPubs []*rsa.PublicKey,
) error {
	var wg sync.WaitGroup
	for _, c := range cosigners {
		peerAddr, err := c.LibP2PAddr()
		if err != nil {
			return err
		}

		x509Bz, err := x509.MarshalPKIXPublicKey(rsaPubs[c.ShardID-1])
		if err != nil {
			return err
		}

		pubKey, err := crypto.UnmarshalRsaPublicKey(x509Bz)
		if err != nil {
			return err
		}

		peerID, err := peer.IDFromPublicKey(pubKey)
		if err != nil {
			return err
		}

		peerinfo, err := peer.AddrInfoFromString(peerAddr + "/p2p/" + peerID.String())
		if err != nil {
			return err
		}

		wg.Add(1)
		go func() {
			defer wg.Done()
			_ = retry.Do(
				func() error {
					return h.Connect(ctx, *peerinfo)
				},
				retry.OnRetry(func(n uint, err error) {
					fmt.Printf("Attempt %d: Failed to connect to cosigner %s: %v\n", n, peerinfo.String(), err)
				}),
				retry.DelayType(retry.BackOffDelay),
				retry.Attempts(0),
				retry.Delay(time.Second),
			)

			fmt.Printf("Connection established with bootstrap node from cosigner %d: %s\n", id, *peerinfo)
		}()
	}
	wg.Wait()
	return nil
}

// LocalDKG simulates a DKG key combination ceremony. TEST USE ONLY.
func LocalDKG(threshold, total uint8) (map[uint8]keygen.Cosigner, error) {
	cosigners := make(map[uint8]keygen.Cosigner)

	var err error
	for i := uint8(1); i <= total; i++ {
		cosigners[i], err = keygen.NewCosigner(i, threshold, total)
		if err != nil {
			return nil, err
		}
	}

	msgsOut1 := make([][]byte, 0, total)

	for _, c := range cosigners {
		msgs1, err := c.Round1()
		if err != nil {
			return nil, err
		}

		msgsOut1 = append(msgsOut1, msgs1...)
	}

	msgsOut2 := make([][]byte, 0, total*(total-1)/2)

	for _, c := range cosigners {
		msgs2, err := c.Round2(msgsOut1)
		if err != nil {
			return nil, err
		}

		msgsOut2 = append(msgsOut2, msgs2...)
	}

	for _, c := range cosigners {
		if err := c.Round3(msgsOut2); err != nil {
			return nil, err
		}
		if err := c.WaitForCompletion(); err != nil {
			return nil, err
		}
	}

	return cosigners, nil
}
