package ics23

import (
	"bytes"
	"crypto"
	"encoding/binary"

	// adds sha256 capability to crypto.SHA256
	_ "crypto/sha256"
	// adds sha512 capability to crypto.SHA512
	_ "crypto/sha512"

	// adds ripemd160 capability to crypto.RIPEMD160
	_ "golang.org/x/crypto/ripemd160"

	"github.com/pkg/errors"
)

// Apply will calculate the leaf hash given the key and value being proven
func (op *LeafOp) Apply(key []byte, value []byte) ([]byte, error) {
	if len(key) == 0 {
		return nil, errors.New("Leaf op needs key")
	}
	if len(value) == 0 {
		return nil, errors.New("Leaf op needs value")
	}
	pkey, err := prepareLeafData(op.PrehashKey, op.Length, key)
	if err != nil {
		return nil, errors.Wrap(err, "prehash key")
	}
	pvalue, err := prepareLeafData(op.PrehashValue, op.Length, value)
	if err != nil {
		return nil, errors.Wrap(err, "prehash value")
	}
	data := append(op.Prefix, pkey...)
	data = append(data, pvalue...)
	return doHash(op.Hash, data)
}

// CheckAgainstSpec will verify the LeafOp is in the format defined in spec
func (op *LeafOp) CheckAgainstSpec(spec *ProofSpec) error {
	lspec := spec.LeafSpec

	if op.Hash != lspec.Hash {
		return errors.Errorf("Unexpected HashOp: %d", op.Hash)
	}
	if op.PrehashKey != lspec.PrehashKey {
		return errors.Errorf("Unexpected PrehashKey: %d", op.PrehashKey)
	}
	if op.PrehashValue != lspec.PrehashValue {
		return errors.Errorf("Unexpected PrehashValue: %d", op.PrehashValue)
	}
	if op.Length != lspec.Length {
		return errors.Errorf("Unexpected LengthOp: %d", op.Length)
	}
	if !bytes.HasPrefix(op.Prefix, lspec.Prefix) {
		return errors.Errorf("Leaf Prefix doesn't start with %X", lspec.Prefix)
	}
	return nil
}

// Apply will calculate the hash of the next step, given the hash of the previous step
func (op *InnerOp) Apply(child []byte) ([]byte, error) {
	if len(child) == 0 {
		return nil, errors.Errorf("Inner op needs child value")
	}
	preimage := append(op.Prefix, child...)
	preimage = append(preimage, op.Suffix...)
	return doHash(op.Hash, preimage)
}

// CheckAgainstSpec will verify the InnerOp is in the format defined in spec
func (op *InnerOp) CheckAgainstSpec(spec *ProofSpec) error {
	if op.Hash != spec.InnerSpec.Hash {
		return errors.Errorf("Unexpected HashOp: %d", op.Hash)
	}

	leafPrefix := spec.LeafSpec.Prefix
	if bytes.HasPrefix(op.Prefix, leafPrefix) {
		return errors.Errorf("Inner Prefix starts with %X", leafPrefix)
	}
	if len(op.Prefix) < int(spec.InnerSpec.MinPrefixLength) {
		return errors.Errorf("InnerOp prefix too short (%d)", len(op.Prefix))
	}
	maxLeftChildBytes := (len(spec.InnerSpec.ChildOrder) - 1) * int(spec.InnerSpec.ChildSize)
	if len(op.Prefix) > int(spec.InnerSpec.MaxPrefixLength)+maxLeftChildBytes {
		return errors.Errorf("InnerOp prefix too long (%d)", len(op.Prefix))
	}
	return nil
}

func prepareLeafData(hashOp HashOp, lengthOp LengthOp, data []byte) ([]byte, error) {
	// TODO: lengthop before or after hash ???
	hdata, err := doHashOrNoop(hashOp, data)
	if err != nil {
		return nil, err
	}
	ldata, err := doLengthOp(lengthOp, hdata)
	return ldata, err
}

// doHashOrNoop will return the preimage untouched if hashOp == NONE,
// otherwise, perform doHash
func doHashOrNoop(hashOp HashOp, preimage []byte) ([]byte, error) {
	if hashOp == HashOp_NO_HASH {
		return preimage, nil
	}
	return doHash(hashOp, preimage)
}

// doHash will preform the specified hash on the preimage.
// if hashOp == NONE, it will return an error (use doHashOrNoop if you want different behavior)
func doHash(hashOp HashOp, preimage []byte) ([]byte, error) {
	switch hashOp {
	case HashOp_SHA256:
		hash := crypto.SHA256.New()
		hash.Write(preimage)
		return hash.Sum(nil), nil
	case HashOp_SHA512:
		hash := crypto.SHA512.New()
		hash.Write(preimage)
		return hash.Sum(nil), nil
	case HashOp_RIPEMD160:
		hash := crypto.RIPEMD160.New()
		hash.Write(preimage)
		return hash.Sum(nil), nil
	case HashOp_BITCOIN:
		// ripemd160(sha256(x))
		sha := crypto.SHA256.New()
		sha.Write(preimage)
		tmp := sha.Sum(nil)
		hash := crypto.RIPEMD160.New()
		hash.Write(tmp)
		return hash.Sum(nil), nil
	case HashOp_SHA512_256:
		hash := crypto.SHA512_256.New()
		hash.Write(preimage)
		return hash.Sum(nil), nil
	}
	return nil, errors.Errorf("Unsupported hashop: %d", hashOp)
}

// doLengthOp will calculate the proper prefix and return it prepended
//   doLengthOp(op, data) -> length(data) || data
func doLengthOp(lengthOp LengthOp, data []byte) ([]byte, error) {
	switch lengthOp {
	case LengthOp_NO_PREFIX:
		return data, nil
	case LengthOp_VAR_PROTO:
		res := append(encodeVarintProto(len(data)), data...)
		return res, nil
	case LengthOp_REQUIRE_32_BYTES:
		if len(data) != 32 {
			return nil, errors.Errorf("Data was %d bytes, not 32", len(data))
		}
		return data, nil
	case LengthOp_REQUIRE_64_BYTES:
		if len(data) != 64 {
			return nil, errors.Errorf("Data was %d bytes, not 64", len(data))
		}
		return data, nil
	case LengthOp_FIXED32_LITTLE:
		res := make([]byte, 4, 4+len(data))
		binary.LittleEndian.PutUint32(res[:4], uint32(len(data)))
		res = append(res, data...)
		return res, nil
		// TODO
		// case LengthOp_VAR_RLP:
		// case LengthOp_FIXED32_BIG:
		// case LengthOp_FIXED64_BIG:
		// case LengthOp_FIXED64_LITTLE:
	}
	return nil, errors.Errorf("Unsupported lengthop: %d", lengthOp)
}

func encodeVarintProto(l int) []byte {
	// avoid multiple allocs for normal case
	res := make([]byte, 0, 8)
	for l >= 1<<7 {
		res = append(res, uint8(l&0x7f|0x80))
		l >>= 7
	}
	res = append(res, uint8(l))
	return res
}
