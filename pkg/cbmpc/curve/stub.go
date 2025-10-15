//go:build !cgo || windows

package curve

import (
	"errors"
	"math/big"
	"runtime"

	"github.com/coinbase/cb-mpc-go/pkg/cbmpc/internal/backend"
)

var errNotBuilt = errors.New("curve: native bindings not built")

// =====================
// Curve enum (shared between CGO and non-CGO builds)
// =====================

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

// =====================
// Scalar stub
// =====================

// Scalar stub implementation for non-CGO builds.
type Scalar struct {
	Bytes []byte
}

// NewScalarFromBytes creates a Scalar from bytes (big-endian).
func NewScalarFromBytes(bytes []byte) (*Scalar, error) {
	return nil, errNotBuilt
}

// NewScalarFromString creates a Scalar from a decimal string.
func NewScalarFromString(str string) (*Scalar, error) {
	return nil, errNotBuilt
}

// String returns the Scalar as a decimal string.
func (s *Scalar) String() string {
	return "0"
}

// BigInt returns the Scalar as a big.Int.
func (s *Scalar) BigInt() *big.Int {
	return big.NewInt(0)
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
		return s.CloneBytes()
	}
	if len(s.Bytes) >= target {
		return s.CloneBytes()
	}
	out := make([]byte, target)
	copy(out[target-len(s.Bytes):], s.Bytes)
	return out
}

// zeroizeBytes overwrites the provided slice with zeros and prevents compiler
// dead store elimination using runtime.KeepAlive.
func zeroizeBytes(buf []byte) {
	for i := range buf {
		buf[i] = 0
	}
	runtime.KeepAlive(buf)
}

// Free zeroizes the scalar bytes and releases references.
func (s *Scalar) Free() {
	if s == nil || len(s.Bytes) == 0 {
		return
	}
	zeroizeBytes(s.Bytes)
	s.Bytes = nil
	runtime.SetFinalizer(s, nil)
}

// =====================
// Point stub
// =====================

// Point stub implementation for non-CGO builds.
type Point struct{}

func NewPointFromBytes(Curve, []byte) (*Point, error) {
	return nil, errNotBuilt
}

func (p *Point) Bytes() ([]byte, error) {
	return nil, errNotBuilt
}

func (p *Point) Curve() Curve {
	return Unknown
}

func (p *Point) Free() {}

// CPtr is a stub for non-CGO builds.
func (p *Point) CPtr() backend.ECCPoint {
	return nil
}

// NewPointFromBackend is a stub for non-CGO builds.
func NewPointFromBackend(backend.ECCPoint) *Point {
	return &Point{}
}

// Mul is a stub for non-CGO builds.
func (p *Point) Mul(*Scalar) (*Point, error) {
	return nil, errNotBuilt
}

// =====================
// EC ElGamal Commitment stub
// =====================

// ECElGamalCom represents an EC ElGamal commitment.
// This is a stub for non-CGO builds.
type ECElGamalCom struct{}

// NewECElGamalCom creates an EC ElGamal commitment from two points (L and R).
// This is a stub that returns an error on non-CGO builds.
func NewECElGamalCom(pointL, pointR *Point) (*ECElGamalCom, error) {
	return nil, errNotBuilt
}

// MakeElGamalCom creates an EC ElGamal commitment using make_commitment.
// This is a stub that returns an error on non-CGO builds.
func MakeElGamalCom(p *Point, m, r *Scalar) (*ECElGamalCom, error) {
	return nil, errNotBuilt
}

// LoadECElGamalCom deserializes an EC ElGamal commitment from bytes.
// This is a stub that returns an error on non-CGO builds.
func LoadECElGamalCom(curve Curve, bytes []byte) (*ECElGamalCom, error) {
	return nil, errNotBuilt
}

// Bytes serializes the EC ElGamal commitment to bytes.
// This is a stub that returns an error on non-CGO builds.
func (c *ECElGamalCom) Bytes() ([]byte, error) {
	return nil, errNotBuilt
}

// PointL extracts the L point from the EC ElGamal commitment.
// This is a stub that returns an error on non-CGO builds.
func (c *ECElGamalCom) PointL() (*Point, error) {
	return nil, errNotBuilt
}

// PointR extracts the R point from the EC ElGamal commitment.
// This is a stub that returns an error on non-CGO builds.
func (c *ECElGamalCom) PointR() (*Point, error) {
	return nil, errNotBuilt
}

// Free releases the resources associated with this EC ElGamal commitment.
// This is a no-op on non-CGO builds.
func (c *ECElGamalCom) Free() {}

// CPtr is a stub for non-CGO builds.
func (c *ECElGamalCom) CPtr() backend.ECElGamalCommitment {
	return nil
}

// Curve is a stub for non-CGO builds.
func (c *ECElGamalCom) Curve() Curve {
	return Unknown
}

// String is a stub for non-CGO builds.
func (c *ECElGamalCom) String() string {
	return "ECElGamalCom(stub)"
}

// =====================
// Curve operations stubs
// =====================

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
