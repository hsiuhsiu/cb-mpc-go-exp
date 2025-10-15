// Package curve provides elliptic curve types and operations for cryptographic protocols.
//
// This package defines a stable public API for elliptic curve operations,
// including curve points (Point), scalar values (Scalar), and various curve-related
// cryptographic primitives. It supports multiple standard curves commonly used in
// blockchain and MPC applications.
//
// # Supported Curves
//
//   - P256 (NIST P-256 / secp256r1)
//   - P384 (NIST P-384 / secp384r1)
//   - P521 (NIST P-521 / secp521r1)
//   - Secp256k1 (Bitcoin curve)
//   - Ed25519 (EdDSA curve)
//
// # Key Types
//
//   - Curve: Enum representing an elliptic curve
//   - Point: Represents a point on an elliptic curve
//   - Scalar: Represents a scalar field element (exponent)
//   - ECElGamalCom: Represents an ElGamal commitment (L, R) pair
//
// # Memory Management
//
// Points, Scalars, and ElGamal commitments must be explicitly freed:
//
//	point, err := curve.Generator(curve.P256)
//	if err != nil {
//	    return err
//	}
//	defer point.Free()
//
// A finalizer is set as a safety net, but explicit cleanup is recommended
// to avoid resource leaks.
//
// # Common Operations
//
//	// Generate random scalar
//	scalar, err := curve.RandomScalar(curve.P256)
//	defer scalar.Free()
//
//	// Multiply generator by scalar: Q = scalar * G
//	point, err := curve.MulGenerator(curve.P256, scalar)
//	defer point.Free()
//
//	// Create ElGamal commitment: (r*G, x*Q + r*G)
//	commitment, err := curve.MakeElGamalCom(basePoint, x, r)
//	defer commitment.Free()
//
// See cb-mpc/src/cbmpc/crypto/ for underlying cryptographic implementations.
package curve
