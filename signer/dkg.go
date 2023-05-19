package signer

import (
	"context"
	"encoding/json"
	"fmt"
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
	"golang.org/x/sync/errgroup"
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
	p2pPrivateKey crypto.PrivKey,
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

	h, err := libp2p.New(libp2p.ListenAddrStrings(hostAddr), libp2p.Identity(p2pPrivateKey))
	if err != nil {
		return nil, fmt.Errorf("failed to construct libp2p node: %w", err)
	}

	defer h.Close()

	fmt.Println("Starting cosigner discovery")

	if err := waitForAllCosigners(ctx, h, cosigners.OtherCosigners(id)); err != nil {
		return nil, err
	}

	fmt.Println("Cosigner discovery complete")

	ps, err := pubsub.NewGossipSub(ctx, h)
	if err != nil {
		return nil, fmt.Errorf("failed to setup libp2p pub sub: %w", err)
	}

	total := len(cosigners)

	keygenCosigner, err := keygen.NewCosigner(id, threshold, uint8(total))
	if err != nil {
		return nil, err
	}

	round1, err := keygenCosigner.Round1()
	if err != nil {
		return nil, err
	}

	round1Msgs := RoundMessages{
		Round:    1,
		ID:       id,
		Messages: round1,
	}

	round1MsgsBz, err := json.Marshal(round1Msgs)
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

	var eg errgroup.Group
	eg.Go(func() error {
		return processRounds(ctx, dkgTopic, sub, keygenCosigner, uint8(total), round1[0])
	})

	if err := dkgTopic.Publish(ctx, round1MsgsBz); err != nil {
		return nil, err
	}

	if err := eg.Wait(); err != nil {
		return nil, err
	}

	return &CosignerEd25519Key{
		PubKey:       cometcryptoed25519.PubKey(keygenCosigner.Public().GroupKey.ToEd25519()),
		PrivateShard: keygenCosigner.Secret().Secret.Bytes(),
		ID:           id,
	}, nil
}

func processRounds(
	ctx context.Context,
	dkgTopic *pubsub.Topic,
	sub *pubsub.Subscription,
	keygenCosigner keygen.Cosigner,
	total uint8,
	myRound1Msg []byte,
) error {
	id := uint8(keygenCosigner.ID)

	allRound1Msgs := make([][]byte, total)

	allRound1Msgs[id-1] = myRound1Msg

	allRound2Msgs := make([][]byte, total*(total-1))

	allRound3Msgs := make([][]byte, total)

RecvRoundMsgsLoop:
	for {
		m, err := sub.Next(ctx)
		if err != nil {
			fmt.Printf("Failed to retrieve next message from topic subscription: %v\n", err)
			continue RecvRoundMsgsLoop
		}
		fmt.Println(m.ReceivedFrom, ": ", string(m.Message.Data))

		var cosignerRoundMsgs RoundMessages
		if err := json.Unmarshal(m.Message.Data, &cosignerRoundMsgs); err != nil {
			fmt.Printf("Failed to unmarshal message from topic subscription: %v\n", err)
			continue RecvRoundMsgsLoop
		}
		cID := cosignerRoundMsgs.ID

		switch cosignerRoundMsgs.Round {
		case 1:
			allRound1Msgs[cID-1] = cosignerRoundMsgs.Messages[0]

			for _, m := range allRound1Msgs {
				if len(m) == 0 {
					continue RecvRoundMsgsLoop
				}
			}

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

			copy(allRound2Msgs[(id-1)*(total-1):id*(total-1)], round2)

			if err := dkgTopic.Publish(ctx, round2MsgsBz); err != nil {
				fmt.Printf("Failed to publish round 2 messages: %v\n", err)
			}

		case 2:
			copy(allRound2Msgs[(cID-1)*(total-1):cID*(total-1)], cosignerRoundMsgs.Messages)

			for _, m := range allRound2Msgs {
				if len(m) == 0 {
					continue RecvRoundMsgsLoop
				}
			}

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

			if err := dkgTopic.Publish(ctx, round3MsgsBz); err != nil {
				fmt.Printf("Failed to publish round 3 result: %v\n", err)
			}

		case 3:
			allRound3Msgs[cID-1] = []byte{0x01}
			for _, m := range allRound3Msgs {
				if len(m) == 0 {
					continue RecvRoundMsgsLoop
				}
			}

			// have success from all cosigners, sharding complete
			return nil
		default:
			fmt.Printf("Unexpected round: %d\n", cosignerRoundMsgs.Round)
		}
	}
}

func waitForAllCosigners(ctx context.Context, h host.Host, cosigners CosignersConfig) error {
	var wg sync.WaitGroup
	for _, c := range cosigners {
		peerAddr, err := c.LibP2PAddr()
		if err != nil {
			return err
		}

		peerinfo, err := peer.AddrInfoFromString(peerAddr + "/p2p/" + c.DKGID)
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

			fmt.Printf("Connection established with bootstrap node: %s\n", *peerinfo)
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
