//go:build !cgo || windows

package curve

import (
	"errors"

	"github.com/coinbase/cb-mpc-go/pkg/cbmpc/internal/backend"
)

// Point stub implementation for non-CGO builds.
type Point struct{}

func NewPointFromBytes(Curve, []byte) (*Point, error) {
	return nil, errors.New("Point requires CGO")
}

func (p *Point) Bytes() ([]byte, error) {
	return nil, errors.New("Point requires CGO")
}

func (p *Point) Curve() Curve {
	return Curve{}
}

func (p *Point) Free() {}

// CPtr is a stub for non-CGO builds.
func (p *Point) CPtr() backend.ECCPoint {
	return nil
}

// NewPointFromBackend is a stub for non-CGO builds.
func NewPointFromBackend(backend.ECCPoint) *Point {
	return &Point{}
}
