//go:build !cgo || windows

package cbmpc

import (
	"errors"
	"math/big"

	"github.com/coinbase/cb-mpc-go/internal/bindings"
)

// This file contains stub implementations for types that require CGO.
// These stubs are used when building without CGO or on Windows.

// CurvePoint stub implementation
// Not available in non-CGO builds.
type CurvePoint struct{}

func NewCurvePointFromBytes(Curve, []byte) (*CurvePoint, error) {
	return nil, errors.New("CurvePoint requires CGO")
}

func (p *CurvePoint) Bytes() ([]byte, error) {
	return nil, errors.New("CurvePoint requires CGO")
}

func (p *CurvePoint) Curve() Curve {
	return Curve{}
}

func (p *CurvePoint) Free() {}

// CPtr is a stub for non-CGO builds.
func (p *CurvePoint) CPtr() bindings.ECCPoint {
	return nil
}

// NewCurvePointFromBindings is a stub for non-CGO builds.
func NewCurvePointFromBindings(bindings.ECCPoint) *CurvePoint {
	return &CurvePoint{}
}

// Scalar stub implementation
// This stub implementation is for non-CGO builds.
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

// KEM is the interface for Key Encapsulation Mechanisms used by PVE.
// This is a stub for non-CGO builds.
type KEM interface {
	Encapsulate(ek []byte, rho [32]byte) (ct, ss []byte, err error)
	Decapsulate(skHandle any, ct []byte) (ss []byte, err error)
	DerivePub(skRef []byte) ([]byte, error)
}

// RSAKEM stub implementation
// Not available in non-CGO builds.
type RSAKEM struct{}

func NewRSAKEM(keySize int) (*RSAKEM, error) {
	return nil, errors.New("RSAKEM requires CGO")
}

func (k *RSAKEM) Generate() (skRef []byte, ek []byte, err error) {
	return nil, nil, errors.New("RSAKEM requires CGO")
}

func (k *RSAKEM) Encapsulate(ek []byte, rho [32]byte) (ct, ss []byte, err error) {
	return nil, nil, errors.New("RSAKEM requires CGO")
}

func (k *RSAKEM) Decapsulate(skHandle any, ct []byte) (ss []byte, err error) {
	return nil, errors.New("RSAKEM requires CGO")
}

func (k *RSAKEM) DerivePub(skRef []byte) ([]byte, error) {
	return nil, errors.New("RSAKEM requires CGO")
}

func (k *RSAKEM) NewPrivateKeyHandle(skRef []byte) (any, error) {
	return nil, errors.New("RSAKEM requires CGO")
}

func (k *RSAKEM) FreePrivateKeyHandle(handle any) error {
	return errors.New("RSAKEM requires CGO")
}
