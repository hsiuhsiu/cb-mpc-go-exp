//go:build !cgo || windows

package cbmpc

import (
	"errors"

	"github.com/coinbase/cb-mpc-go/internal/bindings"
)

// CurvePoint represents an elliptic curve point.
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
