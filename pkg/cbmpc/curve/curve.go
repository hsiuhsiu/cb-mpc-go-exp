//go:build cgo && !windows

package curve

import (
	"errors"
	"runtime"

	"github.com/coinbase/cb-mpc-go/pkg/cbmpc/internal/backend"
)

// Curve represents an elliptic curve for cryptographic operations.
// This is a stable Go enum that is independent of backend implementation details.
type Curve = backend.Curve

// Standard curves supported by the MPC protocols.
// These are re-exported from the backend package for public use.
const (
	Unknown   = backend.Unknown   // Unknown or unsupported curve
	P256      = backend.P256      // NIST P-256 (secp256r1)
	P384      = backend.P384      // NIST P-384 (secp384r1)
	P521      = backend.P521      // NIST P-521 (secp521r1)
	Secp256k1 = backend.Secp256k1 // Bitcoin secp256k1
	Ed25519   = backend.Ed25519   // Ed25519 (Twisted Edwards curve)
)

// RandomScalar generates a cryptographically secure random scalar for the given curve.
// The scalar is suitable for use as a private key or exponent.
// Returns a Scalar that must be freed with Free() when no longer needed.
func RandomScalar(c Curve) (*Scalar, error) {
	nid, err := backend.CurveToNID(c)
	if err != nil {
		return nil, err
	}

	scalarBytes, err := backend.CurveRandomScalar(nid)
	if err != nil {
		return nil, err
	}

	// Create Scalar from the random bytes
	return NewScalarFromBytes(scalarBytes)
}

// Generator returns the generator point for the given curve.
// Returns a Point that must be freed with Free() when no longer needed.
func Generator(c Curve) (*Point, error) {
	nid, err := backend.CurveToNID(c)
	if err != nil {
		return nil, err
	}

	cpoint, err := backend.CurveGetGenerator(nid)
	if err != nil {
		return nil, err
	}

	p := &Point{cpoint: cpoint}
	runtime.SetFinalizer(p, (*Point).Free)
	return p, nil
}

// MulGenerator multiplies the generator point by a scalar: result = scalar * G.
// Returns a Point that must be freed with Free() when no longer needed.
func MulGenerator(c Curve, scalar *Scalar) (*Point, error) {
	if scalar == nil {
		return nil, errors.New("nil scalar")
	}

	nid, err := backend.CurveToNID(c)
	if err != nil {
		return nil, err
	}

	cpoint, err := backend.CurveMulGenerator(nid, scalar.Bytes)
	if err != nil {
		return nil, err
	}

	runtime.KeepAlive(scalar)

	p := &Point{cpoint: cpoint}
	runtime.SetFinalizer(p, (*Point).Free)
	return p, nil
}
