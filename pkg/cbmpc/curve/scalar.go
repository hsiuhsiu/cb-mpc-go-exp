//go:build cgo && !windows

package curve

import (
	"errors"
	"math/big"
	"runtime"

	"github.com/coinbase/cb-mpc-go/pkg/cbmpc/internal/backend"
)

// Scalar represents a cryptographic scalar value.
// This provides constant-time operations unlike big.Int which is not safe for cryptography.
// The scalar is stored as bytes (big-endian), similar to how C++ bn_t stores values.
//
// The Bytes field is publicly accessible for read-only access.
// IMPORTANT: Do not mutate the Bytes field directly as this may lead to undefined behavior.
// To create a Scalar:
//   - Use NewScalarFromBytes() for validation and normalization
//   - Use NewScalarFromString() to parse from decimal strings
//
// If you need to modify bytes, create a new Scalar with the modified bytes.
//
// Concurrency Safety:
//   - Scalar methods are safe to call concurrently from multiple goroutines.
//   - However, calling Free() while another goroutine is using the Scalar is unsafe and will cause
//     use-after-free errors. The caller is responsible for ensuring all operations on a Scalar
//     complete before calling Free().
//   - runtime.KeepAlive in methods prevents premature garbage collection, not user-initiated Free().
//   - Safe pattern: Use defer s.Free() immediately after creation, or ensure exclusive ownership
//     during Free().
type Scalar struct {
	Bytes []byte
}

// zeroizeBytes overwrites the provided slice with zeros and prevents compiler
// dead store elimination using runtime.KeepAlive.
// Local duplicate to avoid import cycles with the top-level cbmpc package.
func zeroizeBytes(buf []byte) {
	for i := range buf {
		buf[i] = 0
	}
	runtime.KeepAlive(buf)
}

// NewScalarFromBytes creates a Scalar from bytes (big-endian).
// The bytes are validated by converting to/from C++ bn_t to ensure correctness.
// The input bytes are copied to prevent external mutation of the Scalar's internal state.
func NewScalarFromBytes(bytes []byte) (*Scalar, error) {
	if len(bytes) == 0 {
		return nil, errors.New("empty bytes")
	}

	// Make a defensive copy of input bytes before processing
	bytesCopy := make([]byte, len(bytes))
	copy(bytesCopy, bytes)

	// Validate by converting to C++ bn_t and back
	// This ensures the bytes represent a valid scalar
	ptr, err := backend.ScalarFromBytes(bytesCopy)
	if err != nil {
		return nil, err
	}
	defer backend.ScalarFree(ptr)

	// Convert back to bytes to get normalized form
	normalizedBytes, err := backend.ScalarToBytes(ptr)
	if err != nil {
		return nil, err
	}

	s := &Scalar{Bytes: normalizedBytes}

	// Ensure sensitive memory is cleared if the Scalar becomes unreachable
	runtime.SetFinalizer(s, (*Scalar).Free)
	return s, nil
}

// NewScalarFromString creates a Scalar from a decimal string.
func NewScalarFromString(str string) (*Scalar, error) {
	if len(str) == 0 {
		return nil, errors.New("empty string")
	}

	// Convert string to C++ bn_t
	ptr, err := backend.ScalarFromString(str)
	if err != nil {
		return nil, err
	}
	defer backend.ScalarFree(ptr)

	// Convert to bytes for storage
	bytes, err := backend.ScalarToBytes(ptr)
	if err != nil {
		return nil, err
	}

	s := &Scalar{Bytes: bytes}
	// Ensure sensitive memory is cleared if the Scalar becomes unreachable
	runtime.SetFinalizer(s, (*Scalar).Free)
	return s, nil
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

// CloneBytes returns a defensive copy of the underlying bytes.
func (s *Scalar) CloneBytes() []byte {
	if s == nil || len(s.Bytes) == 0 {
		return nil
	}
	out := make([]byte, len(s.Bytes))
	copy(out, s.Bytes)
	return out
}

// BytesPadded returns a left-padded big-endian fixed-size representation of the scalar
// for the provided curve. The length is curve.MaxHashSize(). If the scalar's
// normalized byte representation exceeds the target length, the full bytes are
// returned without truncation.
func (s *Scalar) BytesPadded(c Curve) []byte {
	if s == nil {
		return nil
	}
	target := c.MaxHashSize()
	if target <= 0 {
		// Unknown curve; return a clone of the existing bytes
		return s.CloneBytes()
	}
	if len(s.Bytes) >= target {
		return s.CloneBytes()
	}
	out := make([]byte, target)
	copy(out[target-len(s.Bytes):], s.Bytes)
	return out
}

// Free zeroizes the scalar bytes and releases references.
func (s *Scalar) Free() {
	if s == nil || len(s.Bytes) == 0 {
		return
	}
	zeroizeBytes(s.Bytes)
	// Drop reference to allow GC to reclaim the backing array
	s.Bytes = nil
	// Remove finalizer since we've freed
	runtime.SetFinalizer(s, nil)
}

// Add adds two scalars modulo curve order: result = (this + other) mod q.
// Returns a new Scalar that must be freed with Free() when no longer needed.
func (s *Scalar) Add(other *Scalar, curve Curve) (*Scalar, error) {
	if s == nil || len(s.Bytes) == 0 {
		return nil, errors.New("nil scalar")
	}
	if other == nil || len(other.Bytes) == 0 {
		return nil, errors.New("nil other scalar")
	}

	nid, err := backend.CurveToNID(backend.Curve(curve))
	if err != nil {
		return nil, err
	}

	resultBytes, err := backend.ScalarAdd(s.Bytes, other.Bytes, nid)
	if err != nil {
		return nil, err
	}

	runtime.KeepAlive(s)
	runtime.KeepAlive(other)

	result := &Scalar{Bytes: resultBytes}
	runtime.SetFinalizer(result, (*Scalar).Free)
	return result, nil
}
