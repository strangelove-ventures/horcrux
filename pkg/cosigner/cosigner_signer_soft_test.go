package cosigner

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"reflect"
	"testing"
	"time"

	cometproto "github.com/cometbft/cometbft/proto/tendermint/types"
	comet "github.com/cometbft/cometbft/types"
	"github.com/stretchr/testify/require"
	tsed25519 "gitlab.com/unit410/threshold-ed25519/pkg"
)

func TestThresholdSignerSoft_GenerateNonces(t *testing.T) {
	type fields struct {
		privateKeyShard []byte
		pubKey          []byte
		threshold       uint8
		total           uint8
	}
	tests := []struct {
		name    string
		fields  fields
		want    Nonces
		wantErr bool
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := &ThresholdSignerSoft{
				privateKeyShard: tt.fields.privateKeyShard,
				pubKey:          tt.fields.pubKey,
				threshold:       tt.fields.threshold,
				total:           tt.fields.total,
			}
			got, err := s.GenerateNonces()
			if (err != nil) != tt.wantErr {
				t.Errorf("ThresholdSignerSoft.GenerateNonces() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("ThresholdSignerSoft.GenerateNonces() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestSignthreshold25519(test *testing.T) {
	// pack a vote into sign bytes
	var vote cometproto.Vote
	vote.Height = 1
	vote.Round = 0
	vote.Type = cometproto.PrevoteType
	vote.Timestamp = time.Now()

	message := comet.VoteSignBytes("chain-id", &vote)

	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(test, err)

	// persistentshares is the privateKey split into 3 shamir parts
	persistentshares := tsed25519.DealShares(tsed25519.ExpandSecret(privateKey.Seed()), 2, 3)

	// each player generates secret Ri
	r1 := make([]byte, 32)
	_, err = rand.Read(r1)
	require.NoError(test, err)

	r2 := make([]byte, 32)
	_, err = rand.Read(r2)
	require.NoError(test, err)

	r3 := make([]byte, 32)
	_, err = rand.Read(r3)
	require.NoError(test, err)

	// each player split secret per t,n, Rij by Shamir secret sharing
	shares1 := tsed25519.DealShares(r1, 2, 3)
	shares2 := tsed25519.DealShares(r2, 2, 3)
	shares3 := tsed25519.DealShares(r3, 2, 3)

	pub1 := tsed25519.ScalarMultiplyBase(r1)
	pub2 := tsed25519.ScalarMultiplyBase(r2)
	pub3 := tsed25519.ScalarMultiplyBase(r3)

	// B=B1+B2+...Bn
	ephPublicKey := tsed25519.AddElements([]tsed25519.Element{pub1, pub2, pub3})

	// Double check Pubkey
	persistentSharesPub1 := tsed25519.ScalarMultiplyBase(persistentshares[0])
	persistentSharesPub2 := tsed25519.ScalarMultiplyBase(persistentshares[1])
	persistentSharesPub3 := tsed25519.ScalarMultiplyBase(persistentshares[2])

	// A=A1+A2+...An = A=s1⋅B+s2⋅B+...sn⋅B
	publicKey2 := tsed25519.AddElements(
		[]tsed25519.Element{persistentSharesPub1, persistentSharesPub2, persistentSharesPub3})
	// require.Equal(test, publicKey, publicKey_2)

	// each player sends s(i)_{j} to corresponding other player j (i.e. s(1)_{2} to player 2)
	// each player sums all s(i)_{j}, i=1 ... n, j= self id to form their working secret
	s1 := tsed25519.AddScalars([]tsed25519.Scalar{shares1[0], shares2[0], shares3[0]})
	s2 := tsed25519.AddScalars([]tsed25519.Scalar{shares1[1], shares2[1], shares3[1]})
	s3 := tsed25519.AddScalars([]tsed25519.Scalar{shares1[2], shares2[2], shares3[2]})

	_, _ = fmt.Printf("public keys: %x\n", publicKey)
	_, _ = fmt.Printf("public keys: %x\n", publicKey2)
	_, err = fmt.Printf("eph pub: %x\n", ephPublicKey)
	if err != nil {
		panic(err)
	}
	// fmt.Printf("eph secret: %x\n", ephemeralPublic)

	shareSig1 := tsed25519.SignWithShare(message, persistentshares[0], s1, publicKey, ephPublicKey)
	shareSig2 := tsed25519.SignWithShare(message, persistentshares[1], s2, publicKey, ephPublicKey)
	shareSig3 := tsed25519.SignWithShare(message, persistentshares[2], s3, publicKey, ephPublicKey)

	{
		combinedSig := tsed25519.CombineShares(3, []int{1, 2, 3}, [][]byte{shareSig1, shareSig2, shareSig3})
		var signature []byte
		signature = append(signature, ephPublicKey...)
		signature = append(signature, combinedSig...)
		fmt.Println(hex.EncodeToString(signature))
		fmt.Println(ed25519.Verify(publicKey, message, signature))

		if !ed25519.Verify(publicKey, message, signature) {
			test.Error("Invalid Signature for signer [1,2,3]")
		}
	}
	{
		combinedSig := tsed25519.CombineShares(3, []int{1, 2}, [][]byte{shareSig1, shareSig2})
		var signature []byte
		signature = append(signature, ephPublicKey...)
		signature = append(signature, combinedSig...)
		if !ed25519.Verify(publicKey, message, signature) {
			test.Error("Invalid Signature for signer [1,2]")
		}
	}
}
