package mpc

import (
	"crypto/elliptic"
	"fmt"
	"io"
)

// Curve represents supported elliptic curves
type Curve int

const (
	// SECP256K1 is the Bitcoin curve (secp256k1), OpenSSL NID 714
	SECP256K1 Curve = 714

	// SECP256R1 is the NIST P-256 curve (prime256v1), OpenSSL NID 415
	SECP256R1 Curve = 415

	// ED25519 is the Edwards curve, OpenSSL NID 1087
	ED25519 Curve = 1087
)

// String returns the curve name
func (c Curve) String() string {
	switch c {
	case SECP256K1:
		return "secp256k1"
	case SECP256R1:
		return "secp256r1"
	case ED25519:
		return "ed25519"
	default:
		return "unknown"
	}
}

// nid returns the OpenSSL NID for this curve
func (c Curve) nid() int {
	return int(c)
}

// toOpenSSLNID returns the OpenSSL NID for this curve
func (c Curve) toOpenSSLNID() (int, error) {
	switch c {
	case SECP256K1, SECP256R1, ED25519:
		return int(c), nil
	default:
		return 0, fmt.Errorf("unsupported curve: %v", c)
	}
}

// toEllipticCurve returns the Go elliptic.Curve for this curve
func (c Curve) toEllipticCurve() (elliptic.Curve, error) {
	switch c {
	case SECP256K1:
		// secp256k1 is not in Go's standard library
		return nil, fmt.Errorf("secp256k1 not supported by Go's elliptic package")
	case SECP256R1:
		return elliptic.P256(), nil
	case ED25519:
		// Ed25519 is not an elliptic curve in the traditional sense
		return nil, fmt.Errorf("ed25519 not supported by Go's elliptic package")
	default:
		return nil, fmt.Errorf("unsupported curve: %v", c)
	}
}

// Party represents a participant in the MPC protocol
type Party struct {
	ID    string
	Index int
}

// Session represents an MPC computation session with multiple parties
// It handles message routing between parties
type Session interface {
	io.Closer

	// Send sends a message to a specific party
	Send(toParty int, msg []byte) error

	// Receive receives a message from a specific party (blocking)
	Receive(fromParty int) ([]byte, error)

	// ReceiveAll receives messages from multiple parties concurrently
	// This is important for multi-party protocols to avoid blocking on sequential receives
	ReceiveAll(fromParties []int) ([][]byte, error)

	// MyIndex returns this party's index
	MyIndex() int

	// PartyCount returns the total number of parties in this session
	PartyCount() int
}

// KeyShare represents a share of a distributed private key
type KeyShare interface {
	io.Closer

	// PublicKey returns the full public key (same for all parties)
	PublicKey() ([]byte, error)

	// Curve returns the elliptic curve used
	Curve() Curve

	// Marshal serializes the key share for storage
	Marshal() ([]byte, error)
}

// Signature represents a cryptographic signature
type Signature struct {
	R []byte
	S []byte
}

// Marshal returns the signature in standard format (R || S)
func (s *Signature) Marshal() []byte {
	result := make([]byte, len(s.R)+len(s.S))
	copy(result, s.R)
	copy(result[len(s.R):], s.S)
	return result
}
