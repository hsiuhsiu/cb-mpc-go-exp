//go:build !cgo || windows

package curve

import "errors"

var errNotBuilt = errors.New("curve: native bindings not built")

// Curve represents an elliptic curve for cryptographic operations.
// This is a stable Go enum that is independent of backend implementation details.
type Curve int

// Standard curves supported by the MPC protocols.
const (
	Unknown   Curve = iota // Unknown or unsupported curve
	P256                   // NIST P-256 (secp256r1)
	P384                   // NIST P-384 (secp384r1)
	P521                   // NIST P-521 (secp521r1)
	Secp256k1              // Bitcoin secp256k1
	Ed25519                // Ed25519 (Twisted Edwards curve)
)

// String returns a human-readable name for the curve.
func (c Curve) String() string {
	switch c {
	case P256:
		return "P-256"
	case P384:
		return "P-384"
	case P521:
		return "P-521"
	case Secp256k1:
		return "secp256k1"
	case Ed25519:
		return "Ed25519"
	default:
		return "Unknown"
	}
}

// MaxHashSize returns the maximum hash size in bytes for this curve.
// This is the size of the curve order, which is the maximum valid message hash size.
func (c Curve) MaxHashSize() int {
	switch c {
	case P256:
		return 32
	case P384:
		return 48
	case P521:
		return 66
	case Secp256k1:
		return 32
	case Ed25519:
		return 32
	default:
		return 0
	}
}

// RandomScalar stub for non-CGO builds.
func RandomScalar(c Curve) (*Scalar, error) {
	return nil, errNotBuilt
}

// Generator stub for non-CGO builds.
func Generator(c Curve) (*Point, error) {
	return nil, errNotBuilt
}

// MulGenerator stub for non-CGO builds.
func MulGenerator(c Curve, scalar *Scalar) (*Point, error) {
	return nil, errNotBuilt
}
