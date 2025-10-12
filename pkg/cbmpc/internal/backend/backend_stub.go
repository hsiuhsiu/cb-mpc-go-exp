//go:build windows

package backend

import "errors"

// Stub types and functions for Windows builds.
// Note: These are defined in separate !windows files for Unix platforms.

// Curve represents an elliptic curve for cryptographic operations.
type Curve int

const (
	Unknown   Curve = iota
	P256
	P384
	P521
	Secp256k1
	Ed25519
)

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

// Curve mapping functions
func CurveToNID(Curve) (int, error) { return 0, errors.New("unsupported curve") }
func NIDToCurve(int) (Curve, error) { return Unknown, errors.New("unsupported NID") }

// ErrNotBuilt reports that the native bindings were not linked into the
// current binary (Windows build or CGO disabled).
var ErrNotBuilt = errors.New("cbmpc/internal/bindings: native bindings not built")

// ErrBitLeak is returned when E_ECDSA_2P_BIT_LEAK is detected during
// signature verification with global abort. This indicates a potential
// key leak and the key should be considered compromised.
var ErrBitLeak = errors.New("bit leak detected in signature verification")

// Version returns the version string from the native library, or empty if not available.
func Version() string { return "" }
