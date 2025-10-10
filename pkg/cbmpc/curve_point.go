//go:build cgo && !windows

package cbmpc

import (
	"runtime"

	"github.com/coinbase/cb-mpc-go/internal/bindings"
)

// CurvePoint represents an elliptic curve point.
// This wraps the C++ ecc_point_t type and avoids serialization/deserialization overhead.
//
// The point is stored as a C cbmpc_ecc_point (via bindings) and must be freed when no longer needed.
// Use runtime.SetFinalizer or call Free() explicitly to release resources.
type CurvePoint struct {
	// cpoint stores the C pointer as returned from bindings layer
	// The bindings layer uses C.cbmpc_ecc_point, which we store here
	// as an opaque type alias defined in the bindings package
	cpoint bindings.ECCPoint
}

// NewCurvePointFromBytes creates a CurvePoint from compressed bytes.
// The bytes should be in compressed format (33 bytes for 256-bit curves).
func NewCurvePointFromBytes(curve Curve, bytes []byte) (*CurvePoint, error) {
	cpoint, err := bindings.ECCPointFromBytes(curve.NID(), bytes)
	if err != nil {
		return nil, remapError(err)
	}

	p := &CurvePoint{cpoint: cpoint}

	// Set up finalizer to free the point when garbage collected
	runtime.SetFinalizer(p, (*CurvePoint).Free)

	return p, nil
}

// Bytes serializes the CurvePoint to compressed bytes.
func (p *CurvePoint) Bytes() ([]byte, error) {
	if p == nil || p.cpoint == nil {
		return nil, nil
	}

	bytes, err := bindings.ECCPointToBytes(p.cpoint)
	if err != nil {
		return nil, remapError(err)
	}

	return bytes, nil
}

// Curve returns the curve for this point.
func (p *CurvePoint) Curve() Curve {
	if p == nil || p.cpoint == nil {
		return Curve{}
	}

	nid := bindings.ECCPointGetCurveNID(p.cpoint)
	return Curve{nid: nid}
}

// Free releases the resources associated with this CurvePoint.
// This is called automatically by the garbage collector via finalizer,
// but can be called explicitly for immediate cleanup.
func (p *CurvePoint) Free() {
	if p != nil && p.cpoint != nil {
		bindings.ECCPointFree(p.cpoint)
		p.cpoint = nil
		// Clear finalizer since we've already freed
		runtime.SetFinalizer(p, nil)
	}
}

// cPtr returns the internal C pointer for use by bindings.
// This is package-private and should not be exported.
func (p *CurvePoint) cPtr() bindings.ECCPoint {
	if p == nil {
		return nil
	}
	return p.cpoint
}

// newCurvePointFromBindings creates a CurvePoint from a bindings ECCPoint.
// This is package-private and used internally.
func newCurvePointFromBindings(cpoint bindings.ECCPoint) *CurvePoint {
	p := &CurvePoint{cpoint: cpoint}
	runtime.SetFinalizer(p, (*CurvePoint).Free)
	return p
}
