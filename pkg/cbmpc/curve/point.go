//go:build cgo && !windows

package curve

import (
	"errors"
	"runtime"

	"github.com/coinbase/cb-mpc-go/pkg/cbmpc/internal/backend"
)

// Point represents an elliptic curve point.
// This wraps the C++ ecc_point_t type and avoids serialization/deserialization overhead.
//
// The point is stored as a C cbmpc_ecc_point (via backend) and must be freed when no longer needed.
// Use runtime.SetFinalizer or call Free() explicitly to release resources.
type Point struct {
	// cpoint stores the C pointer as returned from backend layer
	// The backend layer uses C.cbmpc_ecc_point, which we store here
	// as an opaque type alias defined in the backend package
	cpoint backend.ECCPoint
}

// NewPointFromBytes creates a Point from compressed bytes.
// The bytes should be in compressed format (33 bytes for 256-bit curves).
func NewPointFromBytes(curve Curve, bytes []byte) (*Point, error) {
	nid, err := backend.CurveToNID(backend.Curve(curve))
	if err != nil {
		return nil, err
	}

	cpoint, err := backend.ECCPointFromBytes(nid, bytes)
	if err != nil {
		return nil, err
	}

	p := &Point{cpoint: cpoint}

	// Set up finalizer to free the point when garbage collected
	runtime.SetFinalizer(p, (*Point).Free)

	return p, nil
}

// Bytes serializes the Point to compressed bytes.
// Returns a defensive copy to prevent external modification of internal data.
func (p *Point) Bytes() ([]byte, error) {
	if p == nil || p.cpoint == nil {
		return nil, errors.New("nil point")
	}

	bytes, err := backend.ECCPointToBytes(p.cpoint)
	if err != nil {
		return nil, err
	}

	// Return a defensive copy to prevent mutation of internal state
	result := make([]byte, len(bytes))
	copy(result, bytes)
	return result, nil
}

// Curve returns the curve for this point.
func (p *Point) Curve() Curve {
	if p == nil || p.cpoint == nil {
		return Unknown
	}

	curve := backend.ECCPointGetCurve(p.cpoint)
	return Curve(curve)
}

// Free releases the resources associated with this Point.
// This is called automatically by the garbage collector via finalizer,
// but can be called explicitly for immediate cleanup.
func (p *Point) Free() {
	if p != nil && p.cpoint != nil {
		backend.ECCPointFree(p.cpoint)
		p.cpoint = nil
		// Clear finalizer since we've already freed
		runtime.SetFinalizer(p, nil)
	}
}

// CPtr returns the internal C pointer for use by protocol subpackages.
// This is exported for use by subpackages that need access to the underlying C pointer.
func (p *Point) CPtr() backend.ECCPoint {
	if p == nil {
		return nil
	}
	return p.cpoint
}

// NewPointFromBackend creates a Point from a backend ECCPoint.
// This is exported for use by protocol subpackages.
func NewPointFromBackend(cpoint backend.ECCPoint) *Point {
	p := &Point{cpoint: cpoint}
	runtime.SetFinalizer(p, (*Point).Free)
	return p
}

// Mul multiplies this point by a scalar: result = scalar * point.
// Returns a new Point that must be freed with Free() when no longer needed.
func (p *Point) Mul(scalar *Scalar) (*Point, error) {
	if p == nil || p.cpoint == nil {
		return nil, errors.New("nil point")
	}
	if scalar == nil {
		return nil, errors.New("nil scalar")
	}

	resultCPoint, err := backend.ECCPointMul(p.cpoint, scalar.Bytes)
	if err != nil {
		return nil, err
	}

	runtime.KeepAlive(p)
	runtime.KeepAlive(scalar)

	result := &Point{cpoint: resultCPoint}
	runtime.SetFinalizer(result, (*Point).Free)
	return result, nil
}
