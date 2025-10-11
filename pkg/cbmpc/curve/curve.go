//go:build cgo && !windows

package curve

import "github.com/coinbase/cb-mpc-go/pkg/cbmpc/internal/backend"

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
