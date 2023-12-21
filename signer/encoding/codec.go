package encoding

import (
	"fmt"

	"github.com/cometbft/cometbft/crypto"
	"github.com/cometbft/cometbft/crypto/ed25519"
	"github.com/cometbft/cometbft/crypto/secp256k1"
	"github.com/cometbft/cometbft/libs/json"
	"github.com/strangelove-ventures/horcrux/v3/signer/bn254"
	"github.com/strangelove-ventures/horcrux/v3/signer/proto"
)

func init() {
	json.RegisterType((*proto.PublicKey_Bn254)(nil), "tendermint.crypto.PublicKey_Bn254")
}

// PubKeyToProto takes crypto.PubKey and transforms it to a protobuf Pubkey
func PubKeyToProto(k crypto.PubKey) (proto.PublicKey, error) {
	var kp proto.PublicKey
	switch k := k.(type) {
	case ed25519.PubKey:
		kp = proto.PublicKey{
			Sum: &proto.PublicKey_Ed25519{
				Ed25519: k,
			},
		}
	case secp256k1.PubKey:
		kp = proto.PublicKey{
			Sum: &proto.PublicKey_Secp256K1{
				Secp256K1: k,
			},
		}
	case bn254.PubKey:
		kp = proto.PublicKey{
			Sum: &proto.PublicKey_Bn254{
				Bn254: k,
			},
		}
	default:
		return kp, fmt.Errorf("toproto: key type %v is not supported", k)
	}
	return kp, nil
}

// PubKeyFromProto takes a protobuf Pubkey and transforms it to a crypto.Pubkey
func PubKeyFromProto(k proto.PublicKey) (crypto.PubKey, error) {
	switch k := k.Sum.(type) {
	case *proto.PublicKey_Ed25519:
		if len(k.Ed25519) != ed25519.PubKeySize {
			return nil, fmt.Errorf("invalid size for PubKeyEd25519. Got %d, expected %d",
				len(k.Ed25519), ed25519.PubKeySize)
		}
		pk := make(ed25519.PubKey, ed25519.PubKeySize)
		copy(pk, k.Ed25519)
		return pk, nil
	case *proto.PublicKey_Secp256K1:
		if len(k.Secp256K1) != secp256k1.PubKeySize {
			return nil, fmt.Errorf("invalid size for PubKeySecp256k1. Got %d, expected %d",
				len(k.Secp256K1), secp256k1.PubKeySize)
		}
		pk := make(secp256k1.PubKey, secp256k1.PubKeySize)
		copy(pk, k.Secp256K1)
		return pk, nil
	case *proto.PublicKey_Bn254:
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
