package encoding

import (
	"fmt"

	"github.com/strangelove-ventures/horcrux/v3/comet/crypto"
	"github.com/strangelove-ventures/horcrux/v3/comet/crypto/bn254"
	"github.com/strangelove-ventures/horcrux/v3/comet/crypto/ed25519"
	"github.com/strangelove-ventures/horcrux/v3/comet/libs/json"
	protocrypto "github.com/strangelove-ventures/horcrux/v3/comet/proto/crypto"
)

func init() {
	json.RegisterType((*protocrypto.PublicKey)(nil), "tendermint.crypto.PublicKey")
	json.RegisterType((*protocrypto.PublicKey_Bn254)(nil), "tendermint.crypto.PublicKey_Bn254")
	json.RegisterType((*protocrypto.PublicKey_Ed25519)(nil), "tendermint.crypto.PublicKey_Ed25519")
}

// PubKeyToProto takes crypto.PubKey and transforms it to a protobuf Pubkey
func PubKeyToProto(k crypto.PubKey) (protocrypto.PublicKey, error) {
	var kp protocrypto.PublicKey
	switch k := k.(type) {
	case ed25519.PubKey:
		kp = protocrypto.PublicKey{
			Sum: &protocrypto.PublicKey_Ed25519{
				Ed25519: k,
			},
		}
	case bn254.PubKey:
		kp = protocrypto.PublicKey{
			Sum: &protocrypto.PublicKey_Bn254{
				Bn254: k,
			},
		}
	default:
		return kp, fmt.Errorf("toproto: key type %v is not supported", k)
	}
	return kp, nil
}

// PubKeyFromProto takes a protobuf Pubkey and transforms it to a crypto.Pubkey
func PubKeyFromProto(k protocrypto.PublicKey) (crypto.PubKey, error) {
	switch k := k.Sum.(type) {
	case *protocrypto.PublicKey_Ed25519:
		if len(k.Ed25519) != ed25519.PubKeySize {
			return nil, fmt.Errorf("invalid size for PubKeyEd25519. Got %d, expected %d",
				len(k.Ed25519), ed25519.PubKeySize)
		}
		pk := make(ed25519.PubKey, ed25519.PubKeySize)
		copy(pk, k.Ed25519)
		return pk, nil
	case *protocrypto.PublicKey_Bn254:
		if len(k.Bn254) != bn254.PubKeySize {
			return nil, fmt.Errorf("invalid size for PubKeyBn254. Got %d, expected %d",
				len(k.Bn254), bn254.PubKeySize)
		}
		pk := make(bn254.PubKey, bn254.PubKeySize)
		copy(pk, k.Bn254)
		return pk, nil
	default:
		return nil, fmt.Errorf("fromproto: key type %v is not supported", k)
	}
}
