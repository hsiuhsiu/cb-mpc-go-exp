//go:build cgo && !windows

package curve

import (
	"encoding/hex"
	"errors"
	"runtime"

	"github.com/coinbase/cb-mpc-go/pkg/cbmpc/internal/backend"
)

// ECElGamalCom represents an EC ElGamal commitment.
// This wraps the C++ ec_elgamal_commitment_t type which is composed of two points (L and R).
//
// The EC ElGamal commitment is stored as a C cbmpc_ec_elgamal_commitment (via backend) and must be freed when no longer needed.
// Use runtime.SetFinalizer or call Free() explicitly to release resources.
//
// Concurrency Safety:
//   - ECElGamalCom methods are safe to call concurrently from multiple goroutines.
//   - However, calling Free() while another goroutine is using the ECElGamalCom is unsafe and will cause
//     use-after-free errors. The caller is responsible for ensuring all operations on an ECElGamalCom
//     complete before calling Free().
//   - runtime.KeepAlive in methods prevents premature garbage collection, not user-initiated Free().
//   - Safe pattern: Use defer c.Free() immediately after creation, or ensure exclusive ownership
//     during Free().
type ECElGamalCom struct {
	// ceccom stores the C pointer as returned from backend layer
	// The backend layer uses C.cbmpc_ec_elgamal_commitment, which we store here
	// as an opaque type alias defined in the backend package
	ceccom backend.ECElGamalCommitment
}

// NewECElGamalCom creates an EC ElGamalcommitment from two points (L and R).
func NewECElGamalCom(pointL, pointR *Point) (*ECElGamalCom, error) {
	if pointL == nil || pointR == nil {
		return nil, errors.New("nil point")
	}

	ceccom, err := backend.ECElGamalCommitmentNew(pointL.cpoint, pointR.cpoint)
	if err != nil {
		return nil, err
	}

	c := &ECElGamalCom{ceccom: ceccom}

	// Set up finalizer to free the EC ElGamal commitment when garbage collected
	runtime.SetFinalizer(c, (*ECElGamalCom).Free)

	runtime.KeepAlive(pointL)
	runtime.KeepAlive(pointR)

	return c, nil
}

// MakeElGamalCom creates an EC ElGamal commitment using make_commitment.
// Creates UV = (r*G, m*P + r*G) where P is the public key point, m is the message scalar, and r is randomness.
func MakeElGamalCom(p *Point, m, r *Scalar) (*ECElGamalCom, error) {
	if p == nil {
		return nil, errors.New("nil point P")
	}
	if m == nil || r == nil {
		return nil, errors.New("nil scalar")
	}

	ceccom, err := backend.ECElGamalCommitmentMake(p.cpoint, m.Bytes, r.Bytes)
	if err != nil {
		return nil, err
	}

	c := &ECElGamalCom{ceccom: ceccom}

	// Set up finalizer to free the EC ElGamal commitment when garbage collected
	runtime.SetFinalizer(c, (*ECElGamalCom).Free)

	runtime.KeepAlive(p)
	runtime.KeepAlive(m)
	runtime.KeepAlive(r)

	return c, nil
}

// LoadECElGamalCom deserializes an EC ElGamal commitment from bytes.
// The bytes should be in the format produced by Bytes().
func LoadECElGamalCom(curve Curve, bytes []byte) (*ECElGamalCom, error) {
	nid, err := backend.CurveToNID(backend.Curve(curve))
	if err != nil {
		return nil, err
	}

	ceccom, err := backend.ECElGamalCommitmentFromBytes(nid, bytes)
	if err != nil {
		return nil, err
	}

	c := &ECElGamalCom{ceccom: ceccom}

	// Set up finalizer to free the EC ElGamal commitment when garbage collected
	runtime.SetFinalizer(c, (*ECElGamalCom).Free)

	return c, nil
}

// Bytes serializes the EC ElGamal commitment to bytes.
// Returns a defensive copy to prevent external modification of internal data.
func (c *ECElGamalCom) Bytes() ([]byte, error) {
	if c == nil || c.ceccom == nil {
		return nil, errors.New("nil EC ElGamal commitment")
	}

	bytes, err := backend.ECElGamalCommitmentToBytes(c.ceccom)
	if err != nil {
		return nil, err
	}

	// Return a defensive copy to prevent mutation of internal state
	result := make([]byte, len(bytes))
	copy(result, bytes)
	return result, nil
}

// PointL extracts the L point from the EC ElGamal commitment.
// Returns a NEW point that must be freed with Free() when no longer needed.
func (c *ECElGamalCom) PointL() (*Point, error) {
	if c == nil || c.ceccom == nil {
		return nil, errors.New("nil EC ElGamal commitment")
	}

	cpoint, err := backend.ECElGamalCommitmentGetL(c.ceccom)
	if err != nil {
		return nil, err
	}

	runtime.KeepAlive(c)

	p := &Point{cpoint: cpoint}
	runtime.SetFinalizer(p, (*Point).Free)
	return p, nil
}

// PointR extracts the R point from the EC ElGamal commitment.
// Returns a NEW point that must be freed with Free() when no longer needed.
func (c *ECElGamalCom) PointR() (*Point, error) {
	if c == nil || c.ceccom == nil {
		return nil, errors.New("nil EC ElGamal commitment")
	}

	cpoint, err := backend.ECElGamalCommitmentGetR(c.ceccom)
	if err != nil {
		return nil, err
	}

	runtime.KeepAlive(c)

	p := &Point{cpoint: cpoint}
	runtime.SetFinalizer(p, (*Point).Free)
	return p, nil
}

// Free releases the resources associated with this EC ElGamal commitment.
// This is called automatically by the garbage collector via finalizer,
// but can be called explicitly for immediate cleanup.
func (c *ECElGamalCom) Free() {
	if c != nil && c.ceccom != nil {
		backend.ECElGamalCommitmentFree(c.ceccom)
		c.ceccom = nil
		// Clear finalizer since we've already freed
		runtime.SetFinalizer(c, nil)
	}
}

// CPtr returns the internal C pointer for use by protocol subpackages.
// This is exported for use by subpackages that need access to the underlying C pointer.
func (c *ECElGamalCom) CPtr() backend.ECElGamalCommitment {
	if c == nil {
		return nil
	}
	return c.ceccom
}

// Curve returns the curve for this EC ElGamal commitment.
// This is determined by extracting the L point and checking its curve.
func (c *ECElGamalCom) Curve() Curve {
	if c == nil || c.ceccom == nil {
		return Unknown
	}

	// Extract L point to determine the curve
	pointL, err := c.PointL()
	if err != nil {
		return Unknown
	}
	defer pointL.Free()

	return pointL.Curve()
}

// String returns a short identifier for the commitment for logging/debugging.
// Returns "ECElGamalCom(<first 8 hex chars of serialized form>)" or "ECElGamalCom(nil)" if the commitment is nil.
// This is safe for logging as it does not leak the actual commitment values.
func (c *ECElGamalCom) String() string {
	if c == nil || c.ceccom == nil {
		return "ECElGamalCom(nil)"
	}

	// Get serialized bytes
	bytes, err := c.Bytes()
	if err != nil {
		return "ECElGamalCom(error)"
	}

	// Return first 8 hex characters as identifier
	if len(bytes) < 4 {
		return "ECElGamalCom(" + hex.EncodeToString(bytes) + ")"
	}
	return "ECElGamalCom(" + hex.EncodeToString(bytes[:4]) + ")"
}
