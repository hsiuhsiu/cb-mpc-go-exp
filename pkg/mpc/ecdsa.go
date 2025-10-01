package mpc

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"fmt"
	"math/big"

	"github.com/coinbase/cb-mpc-go/internal/cgo"
)

// ECDSA2PC represents a two-party ECDSA protocol instance
type ECDSA2PC struct {
	curve Curve
}

// NewECDSA2PC creates a new two-party ECDSA protocol instance
func NewECDSA2PC(curve Curve) *ECDSA2PC {
	return &ECDSA2PC{curve: curve}
}

// ECDSA2PKey represents a distributed ECDSA key share
type ECDSA2PKey struct {
	cgoKey    *cgo.ECDSA2PKey
	curve     Curve
	role      int
	pubKey    []byte
	privShare []byte
}

// KeyGen performs distributed key generation between two parties
func (e *ECDSA2PC) KeyGen(ctx context.Context, session Session) (KeyShare, error) {
	if ctx == nil {
		return nil, fmt.Errorf("context cannot be nil")
	}
	if session == nil {
		return nil, fmt.Errorf("session cannot be nil")
	}
	if session.PartyCount() != 2 {
		return nil, fmt.Errorf("ECDSA 2PC requires exactly 2 parties, got %d", session.PartyCount())
	}

	// Map our curve to OpenSSL NID
	curveCode, err := e.curve.toOpenSSLNID()
	if err != nil {
		return nil, fmt.Errorf("unsupported curve: %v", err)
	}

	// Check for context cancellation
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	default:
	}

	// Perform DKG
	cgoKey, err := cgo.ECDSA2PKeyGen(session, curveCode)
	if err != nil {
		return nil, fmt.Errorf("keygen failed: %v", err)
	}

	// Get key metadata
	role := cgoKey.GetRole()
	pubKey, err := cgoKey.GetPublicKey()
	if err != nil {
		cgoKey.Close()
		return nil, fmt.Errorf("failed to get public key: %v", err)
	}

	privShare, err := cgoKey.GetPrivateShare()
	if err != nil {
		cgoKey.Close()
		return nil, fmt.Errorf("failed to get private share: %v", err)
	}

	return &ECDSA2PKey{
		cgoKey:    cgoKey,
		curve:     e.curve,
		role:      role,
		pubKey:    pubKey,
		privShare: privShare,
	}, nil
}

// Sign creates a distributed ECDSA signature
func (k *ECDSA2PKey) Sign(ctx context.Context, session Session, message []byte) ([]byte, error) {
	if ctx == nil {
		return nil, fmt.Errorf("context cannot be nil")
	}
	if session == nil {
		return nil, fmt.Errorf("session cannot be nil")
	}
	if len(message) == 0 {
		return nil, fmt.Errorf("message cannot be empty")
	}

	// Hash the message
	hash := sha256.Sum256(message)

	// Check for context cancellation
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	default:
	}

	// Perform distributed signing
	signature, err := k.cgoKey.Sign(session, hash[:])
	if err != nil {
		return nil, fmt.Errorf("signing failed: %v", err)
	}

	return signature, nil
}

// SignHash creates a distributed ECDSA signature for a pre-hashed message
func (k *ECDSA2PKey) SignHash(ctx context.Context, session Session, messageHash []byte) ([]byte, error) {
	if ctx == nil {
		return nil, fmt.Errorf("context cannot be nil")
	}
	if session == nil {
		return nil, fmt.Errorf("session cannot be nil")
	}
	if len(messageHash) == 0 {
		return nil, fmt.Errorf("message hash cannot be empty")
	}

	// Check for context cancellation
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	default:
	}

	// Perform distributed signing
	signature, err := k.cgoKey.Sign(session, messageHash)
	if err != nil {
		return nil, fmt.Errorf("signing failed: %v", err)
	}

	return signature, nil
}

// Refresh creates a new key share with the same public key
func (k *ECDSA2PKey) Refresh(ctx context.Context, session Session) (KeyShare, error) {
	if ctx == nil {
		return nil, fmt.Errorf("context cannot be nil")
	}
	if session == nil {
		return nil, fmt.Errorf("session cannot be nil")
	}

	// Check for context cancellation
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	default:
	}

	// Perform refresh
	newCgoKey, err := k.cgoKey.Refresh(session)
	if err != nil {
		return nil, fmt.Errorf("refresh failed: %v", err)
	}

	// Get new key metadata
	role := newCgoKey.GetRole()
	pubKey, err := newCgoKey.GetPublicKey()
	if err != nil {
		newCgoKey.Close()
		return nil, fmt.Errorf("failed to get public key: %v", err)
	}

	privShare, err := newCgoKey.GetPrivateShare()
	if err != nil {
		newCgoKey.Close()
		return nil, fmt.Errorf("failed to get private share: %v", err)
	}

	return &ECDSA2PKey{
		cgoKey:    newCgoKey,
		curve:     k.curve,
		role:      role,
		pubKey:    pubKey,
		privShare: privShare,
	}, nil
}

// GetPublicKey returns the full public key as raw bytes
func (k *ECDSA2PKey) GetPublicKey() []byte {
	// Return a copy to prevent modification
	result := make([]byte, len(k.pubKey))
	copy(result, k.pubKey)
	return result
}

// PublicKey implements KeyShare interface
func (k *ECDSA2PKey) PublicKey() ([]byte, error) {
	return k.GetPublicKey(), nil
}

// Curve implements KeyShare interface
func (k *ECDSA2PKey) Curve() Curve {
	return k.curve
}

// Marshal implements KeyShare interface
func (k *ECDSA2PKey) Marshal() ([]byte, error) {
	// TODO: Implement serialization
	return nil, fmt.Errorf("Marshal not implemented")
}

// GetPublicKeyECDSA converts the public key to Go's ecdsa.PublicKey format
func (k *ECDSA2PKey) GetPublicKeyECDSA() (*ecdsa.PublicKey, error) {
	// Get the elliptic curve
	curve, err := k.curve.toEllipticCurve()
	if err != nil {
		return nil, fmt.Errorf("unsupported curve: %v", err)
	}

	// Parse compressed point
	if len(k.pubKey) == 0 {
		return nil, fmt.Errorf("public key is empty")
	}

	x, y := elliptic.Unmarshal(curve, k.pubKey)
	if x == nil || y == nil {
		// Try uncompressed format
		x, y = elliptic.UnmarshalCompressed(curve, k.pubKey)
		if x == nil || y == nil {
			return nil, fmt.Errorf("failed to unmarshal public key")
		}
	}

	return &ecdsa.PublicKey{
		Curve: curve,
		X:     x,
		Y:     y,
	}, nil
}

// GetRole returns the party role (0 or 1)
func (k *ECDSA2PKey) GetRole() int {
	return k.role
}

// GetCurve returns the curve used by this key
func (k *ECDSA2PKey) GetCurve() Curve {
	return k.curve
}

// Close releases the key resources
func (k *ECDSA2PKey) Close() error {
	if k.cgoKey != nil {
		return k.cgoKey.Close()
	}
	return nil
}

// VerifySignature verifies an ECDSA signature against a message
func (k *ECDSA2PKey) VerifySignature(message, signature []byte) error {
	// Hash the message
	hash := sha256.Sum256(message)
	return k.VerifySignatureHash(hash[:], signature)
}

// VerifySignatureHash verifies an ECDSA signature against a pre-hashed message
func (k *ECDSA2PKey) VerifySignatureHash(messageHash, signature []byte) error {
	// Get the public key in Go format
	pubKey, err := k.GetPublicKeyECDSA()
	if err != nil {
		return fmt.Errorf("failed to get public key: %v", err)
	}

	// Parse DER signature
	r, s, err := parseDERSignature(signature)
	if err != nil {
		return fmt.Errorf("failed to parse signature: %v", err)
	}

	// Verify signature
	if !ecdsa.Verify(pubKey, messageHash, r, s) {
		return fmt.Errorf("signature verification failed")
	}

	return nil
}

// parseDERSignature parses a DER-encoded ECDSA signature
func parseDERSignature(sig []byte) (*big.Int, *big.Int, error) {
	if len(sig) < 8 {
		return nil, nil, fmt.Errorf("signature too short")
	}

	// Simple DER parsing - should be improved for production
	// DER: 0x30 [total-length] 0x02 [R-length] [R] 0x02 [S-length] [S]
	if sig[0] != 0x30 {
		return nil, nil, fmt.Errorf("invalid DER signature: missing SEQUENCE tag")
	}

	totalLen := int(sig[1])
	if len(sig) != totalLen+2 {
		return nil, nil, fmt.Errorf("invalid DER signature: incorrect length")
	}

	offset := 2
	if offset >= len(sig) || sig[offset] != 0x02 {
		return nil, nil, fmt.Errorf("invalid DER signature: missing INTEGER tag for r")
	}
	offset++

	rLen := int(sig[offset])
	offset++
	if offset+rLen > len(sig) {
		return nil, nil, fmt.Errorf("invalid DER signature: r length exceeds signature")
	}

	r := new(big.Int).SetBytes(sig[offset : offset+rLen])
	offset += rLen

	if offset >= len(sig) || sig[offset] != 0x02 {
		return nil, nil, fmt.Errorf("invalid DER signature: missing INTEGER tag for s")
	}
	offset++

	sLen := int(sig[offset])
	offset++
	if offset+sLen != len(sig) {
		return nil, nil, fmt.Errorf("invalid DER signature: s length mismatch")
	}

	s := new(big.Int).SetBytes(sig[offset:])

	return r, s, nil
}

// UnmarshalKeyShare deserializes a key share from bytes
func (e *ECDSA2PC) UnmarshalKeyShare(data []byte) (KeyShare, error) {
	// TODO: Implement serialization/deserialization
	return nil, errorf("UnmarshalKeyShare", "not implemented")
}

// ECDSAMP provides multi-party threshold ECDSA operations
type ECDSAMP struct {
	curve     Curve
	threshold int // Minimum number of parties needed to sign
	parties   int // Total number of parties
}

// NewECDSAMP creates a new multi-party threshold ECDSA instance
func NewECDSAMP(curve Curve, threshold, parties int) (*ECDSAMP, error) {
	if threshold < 1 || threshold > parties {
		return nil, ErrInvalidParameter
	}
	return &ECDSAMP{
		curve:     curve,
		threshold: threshold,
		parties:   parties,
	}, nil
}

// KeyGen performs distributed key generation among multiple parties
// All parties must call this simultaneously with the same session
func (e *ECDSAMP) KeyGen(ctx context.Context, session Session) (KeyShare, error) {
	// TODO: Implement via internal/cgo
	return nil, errorf("KeyGen", "not implemented")
}

// Sign generates a threshold signature on a message
// At least threshold parties must call this simultaneously
func (e *ECDSAMP) Sign(ctx context.Context, session Session, keyShare KeyShare, messageHash []byte) (*Signature, error) {
	// TODO: Implement via internal/cgo
	return nil, errorf("Sign", "not implemented")
}

// UnmarshalKeyShare deserializes a key share from bytes
func (e *ECDSAMP) UnmarshalKeyShare(data []byte) (KeyShare, error) {
	// TODO: Implement via internal/cgo
	return nil, errorf("UnmarshalKeyShare", "not implemented")
}
