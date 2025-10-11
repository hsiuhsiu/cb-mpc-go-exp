//go:build !cgo || windows

package curve

import (
	"errors"
	"math/big"
)

// Scalar stub implementation for non-CGO builds.
type Scalar struct {
	Bytes []byte
}

// NewScalarFromBytes creates a Scalar from bytes (big-endian).
func NewScalarFromBytes(bytes []byte) (*Scalar, error) {
	return nil, errors.New("not built with CGO")
}

// NewScalarFromString creates a Scalar from a decimal string.
func NewScalarFromString(str string) (*Scalar, error) {
	return nil, errors.New("not built with CGO")
}

// String returns the Scalar as a decimal string.
func (s *Scalar) String() string {
	return "0"
}

// BigInt returns the Scalar as a big.Int.
func (s *Scalar) BigInt() *big.Int {
	return big.NewInt(0)
}

// Free is a no-op for compatibility.
func (s *Scalar) Free() {}
