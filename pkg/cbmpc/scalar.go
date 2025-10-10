//go:build cgo && !windows

package cbmpc

import (
	"errors"
	"math/big"

	"github.com/coinbase/cb-mpc-go/internal/bindings"
)

// Scalar represents a cryptographic scalar value.
// This provides constant-time operations unlike big.Int which is not safe for cryptography.
// The scalar is stored as bytes (big-endian), similar to how C++ bn_t stores values.
//
// The Bytes field is publicly accessible. You can:
//   - Create directly: &Scalar{Bytes: myBytes} if you know the bytes are valid
//   - Use NewScalarFromBytes() for validation and normalization
//   - Use NewScalarFromString() to parse from decimal strings
type Scalar struct {
	Bytes []byte
}

// NewScalarFromBytes creates a Scalar from bytes (big-endian).
// The bytes are validated by converting to/from C++ bn_t to ensure correctness.
func NewScalarFromBytes(bytes []byte) (*Scalar, error) {
	if len(bytes) == 0 {
		return nil, errors.New("empty bytes")
	}

	// Validate by converting to C++ bn_t and back
	// This ensures the bytes represent a valid scalar
	ptr, err := bindings.ScalarFromBytes(bytes)
	if err != nil {
		return nil, RemapError(err)
	}
	defer bindings.ScalarFree(ptr)

	// Convert back to bytes to get normalized form
	normalizedBytes, err := bindings.ScalarToBytes(ptr)
	if err != nil {
		return nil, RemapError(err)
	}

	return &Scalar{Bytes: normalizedBytes}, nil
}

// NewScalarFromString creates a Scalar from a decimal string.
func NewScalarFromString(str string) (*Scalar, error) {
	if len(str) == 0 {
		return nil, errors.New("empty string")
	}

	// Convert string to C++ bn_t
	ptr, err := bindings.ScalarFromString(str)
	if err != nil {
		return nil, RemapError(err)
	}
	defer bindings.ScalarFree(ptr)

	// Convert to bytes for storage
	bytes, err := bindings.ScalarToBytes(ptr)
	if err != nil {
		return nil, RemapError(err)
	}

	return &Scalar{Bytes: bytes}, nil
}

// String returns the Scalar as a decimal string.
func (s *Scalar) String() string {
	if s == nil || len(s.Bytes) == 0 {
		return "0"
	}

	// Convert bytes to big.Int for string representation
	// This is safe for display purposes (not used in cryptographic operations)
	bigInt := new(big.Int).SetBytes(s.Bytes)
	return bigInt.String()
}

// BigInt returns the Scalar as a big.Int.
// WARNING: big.Int operations are NOT constant-time and should not be used
// for cryptographic operations. This is provided for convenience and debugging only.
func (s *Scalar) BigInt() *big.Int {
	if s == nil || len(s.Bytes) == 0 {
		return big.NewInt(0)
	}

	// Return a copy to prevent external modification affecting the Scalar
	return new(big.Int).SetBytes(s.Bytes)
}

// Free is a no-op for compatibility with the old pointer-based implementation.
// Since Scalar now uses []byte, no manual cleanup is needed.
func (s *Scalar) Free() {
	// No-op: bytes are managed by Go's garbage collector
}
