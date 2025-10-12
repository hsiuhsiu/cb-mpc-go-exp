//go:build !cgo || windows

package curve

import (
	"errors"
	"math/big"
	"runtime"
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

// CloneBytes returns a defensive copy of the underlying bytes.
func (s *Scalar) CloneBytes() []byte {
	if s == nil || len(s.Bytes) == 0 {
		return nil
	}
	out := make([]byte, len(s.Bytes))
	copy(out, s.Bytes)
	return out
}

// BytesPadded returns a left-padded big-endian fixed-size representation of the scalar
// for the provided curve. The length is curve.MaxHashSize(). If the scalar's
// normalized byte representation exceeds the target length, the full bytes are
// returned without truncation.
func (s *Scalar) BytesPadded(c Curve) []byte {
	if s == nil {
		return nil
	}
	target := c.MaxHashSize()
	if target <= 0 {
		return s.CloneBytes()
	}
	if len(s.Bytes) >= target {
		return s.CloneBytes()
	}
	out := make([]byte, target)
	copy(out[target-len(s.Bytes):], s.Bytes)
	return out
}

// zeroizeBytes overwrites the provided slice with zeros and prevents compiler
// dead store elimination using runtime.KeepAlive.
func zeroizeBytes(buf []byte) {
	for i := range buf {
		buf[i] = 0
	}
	runtime.KeepAlive(buf)
}

// Free zeroizes the scalar bytes and releases references.
func (s *Scalar) Free() {
	if s == nil || len(s.Bytes) == 0 {
		return
	}
	zeroizeBytes(s.Bytes)
	s.Bytes = nil
	runtime.SetFinalizer(s, nil)
}
