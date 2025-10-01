package mpc

import (
	"crypto/subtle"
	"encoding/hex"
	"fmt"
)

// Scalar represents a big integer used in cryptographic operations.
// Unlike big.Int, Scalar operations aim for constant-time execution to prevent timing attacks.
// Scalars are immutable - all operations return new Scalars.
//
// Internally, scalars are stored as big-endian byte slices.
// The underlying C++ library uses bn_t (arbitrary precision) or mod_t (modular arithmetic).
type Scalar struct {
	data []byte // Big-endian representation
}

// NewScalar creates a Scalar from a big-endian byte slice.
// The input is copied to ensure immutability.
func NewScalar(data []byte) *Scalar {
	if len(data) == 0 {
		return &Scalar{data: []byte{0}}
	}
	// Copy to ensure immutability
	dataCopy := make([]byte, len(data))
	copy(dataCopy, data)
	return &Scalar{data: dataCopy}
}

// NewScalarInt64 creates a Scalar from an int64 value.
// This is a convenience function for small constants.
func NewScalarInt64(value int64) *Scalar {
	// Direct implementation without CGO for simple case
	// We'll use big-endian encoding
	if value == 0 {
		return &Scalar{data: []byte{0}}
	}

	// Convert to bytes
	var bytes []byte
	v := value
	negative := v < 0
	if negative {
		v = -v
	}

	for v > 0 {
		bytes = append([]byte{byte(v & 0xFF)}, bytes...)
		v >>= 8
	}

	s := &Scalar{data: bytes}
	if negative {
		// For negative numbers, we'd need to handle via CGO
		// For now, just panic
		panic("negative scalars not yet implemented")
	}
	return s
}

// Bytes returns the big-endian byte representation of the scalar.
// The returned slice is a copy to preserve immutability.
func (s *Scalar) Bytes() []byte {
	result := make([]byte, len(s.data))
	copy(result, s.data)
	return result
}

// String returns the hexadecimal representation of the scalar.
func (s *Scalar) String() string {
	return hex.EncodeToString(s.data)
}

// Equal returns true if two scalars are equal.
// Uses constant-time comparison to prevent timing attacks.
func (s *Scalar) Equal(other *Scalar) bool {
	return subtle.ConstantTimeCompare(s.data, other.data) == 1
}

// IsZero returns true if the scalar is zero.
func (s *Scalar) IsZero() bool {
	for _, b := range s.data {
		if b != 0 {
			return false
		}
	}
	return true
}

// Add returns s + other (arbitrary precision).
// For modular arithmetic, use Curve.AddMod().
func (s *Scalar) Add(other *Scalar) (*Scalar, error) {
	// TODO: Implement via internal/cgo
	return nil, errorf("Add", "not implemented")
}

// Sub returns s - other (arbitrary precision).
// For modular arithmetic, use Curve.SubMod().
func (s *Scalar) Sub(other *Scalar) (*Scalar, error) {
	// TODO: Implement via internal/cgo
	return nil, errorf("Sub", "not implemented")
}

// Mul returns s * other (arbitrary precision).
// For modular arithmetic, use Curve.MulMod().
func (s *Scalar) Mul(other *Scalar) (*Scalar, error) {
	// TODO: Implement via internal/cgo
	return nil, errorf("Mul", "not implemented")
}

// Neg returns -s.
func (s *Scalar) Neg() (*Scalar, error) {
	// TODO: Implement via internal/cgo
	return nil, errorf("Neg", "not implemented")
}

// AddMod returns (s + other) mod curve.Order() in constant time.
// This is the most common operation for ECDSA scalar arithmetic.
func (s *Scalar) AddMod(other *Scalar, curve Curve) (*Scalar, error) {
	// TODO: Implement via internal/cgo
	return nil, errorf("AddMod", "not implemented")
}

// SubMod returns (s - other) mod curve.Order() in constant time.
func (s *Scalar) SubMod(other *Scalar, curve Curve) (*Scalar, error) {
	// TODO: Implement via internal/cgo
	return nil, errorf("SubMod", "not implemented")
}

// MulMod returns (s * other) mod curve.Order() in constant time.
func (s *Scalar) MulMod(other *Scalar, curve Curve) (*Scalar, error) {
	// TODO: Implement via internal/cgo
	return nil, errorf("MulMod", "not implemented")
}

// InvMod returns the modular inverse s^-1 mod curve.Order() in constant time.
// Returns an error if s is zero or not coprime with the modulus.
func (s *Scalar) InvMod(curve Curve) (*Scalar, error) {
	// TODO: Implement via internal/cgo
	return nil, errorf("InvMod", "not implemented")
}

// RandomScalar generates a random scalar modulo curve.Order().
func RandomScalar(curve Curve) (*Scalar, error) {
	// TODO: Implement via internal/cgo
	return nil, errorf("RandomScalar", "not implemented")
}

// CurvePoint represents a point on an elliptic curve.
// Points are immutable - all operations return new points.
//
// Internally wraps ecc_point_t from the C++ library.
type CurvePoint struct {
	// We'll store the handle here when implementing CGO
	// For now, just store serialized form for testing
	data  []byte
	curve Curve
}

// PointFromBytes deserializes a curve point from bytes.
// The format depends on the curve (compressed or uncompressed).
func PointFromBytes(data []byte, curve Curve) (*CurvePoint, error) {
	if len(data) == 0 {
		return nil, ErrInvalidParameter
	}
	// TODO: Implement via internal/cgo
	// For now, just store the data
	dataCopy := make([]byte, len(data))
	copy(dataCopy, data)
	return &CurvePoint{data: dataCopy, curve: curve}, nil
}

// Generator returns the generator point G for the curve.
func Generator(curve Curve) (*CurvePoint, error) {
	// TODO: Implement via internal/cgo
	return nil, errorf("Generator", "not implemented")
}

// Bytes returns the serialized representation of the point.
func (p *CurvePoint) Bytes() []byte {
	result := make([]byte, len(p.data))
	copy(result, p.data)
	return result
}

// String returns a hexadecimal representation of the point.
func (p *CurvePoint) String() string {
	return hex.EncodeToString(p.data)
}

// Curve returns the curve this point belongs to.
func (p *CurvePoint) Curve() Curve {
	return p.curve
}

// Equal returns true if two points are equal.
func (p *CurvePoint) Equal(other *CurvePoint) bool {
	// TODO: Should use constant-time comparison from C++ library
	return subtle.ConstantTimeCompare(p.data, other.data) == 1
}

// IsInfinity returns true if this is the point at infinity (identity element).
func (p *CurvePoint) IsInfinity() bool {
	// TODO: Implement via internal/cgo
	return false
}

// X returns the X coordinate as a Scalar.
func (p *CurvePoint) X() (*Scalar, error) {
	// TODO: Implement via internal/cgo
	return nil, errorf("X", "not implemented")
}

// Y returns the Y coordinate as a Scalar.
func (p *CurvePoint) Y() (*Scalar, error) {
	// TODO: Implement via internal/cgo
	return nil, errorf("Y", "not implemented")
}

// Add returns p + other (point addition).
func (p *CurvePoint) Add(other *CurvePoint) (*CurvePoint, error) {
	if p.curve != other.curve {
		return nil, fmt.Errorf("cannot add points from different curves")
	}
	// TODO: Implement via internal/cgo
	return nil, errorf("Add", "not implemented")
}

// Sub returns p - other (point subtraction).
func (p *CurvePoint) Sub(other *CurvePoint) (*CurvePoint, error) {
	if p.curve != other.curve {
		return nil, fmt.Errorf("cannot subtract points from different curves")
	}
	// TODO: Implement via internal/cgo
	return nil, errorf("Sub", "not implemented")
}

// Mul returns scalar * p (scalar multiplication).
// This is a constant-time operation.
func (p *CurvePoint) Mul(scalar *Scalar) (*CurvePoint, error) {
	// TODO: Implement via internal/cgo
	return nil, errorf("Mul", "not implemented")
}

// MulGenerator returns scalar * G where G is the generator point.
// This is more efficient than Mul() on the generator.
func MulGenerator(scalar *Scalar, curve Curve) (*CurvePoint, error) {
	// TODO: Implement via internal/cgo
	return nil, errorf("MulGenerator", "not implemented")
}

// Neg returns -p (point negation).
func (p *CurvePoint) Neg() (*CurvePoint, error) {
	// TODO: Implement via internal/cgo
	return nil, errorf("Neg", "not implemented")
}
