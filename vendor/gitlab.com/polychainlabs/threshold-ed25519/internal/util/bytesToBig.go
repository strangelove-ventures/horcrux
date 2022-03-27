package util

import "math/big"

// BytesToBig converts bytes (little endian) to big.Int
func BytesToBig(bytes []byte) *big.Int {
	var result big.Int
	result.SetBytes(Reverse(bytes))
	return &result
}
