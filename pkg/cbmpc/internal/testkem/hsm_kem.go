//go:build cgo && !windows

package testkem

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"errors"
	"fmt"
	"sync"
)

// SimulatedHSM simulates a Hardware Security Module with key isolation.
// Keys are identified by handles and never leave the "HSM".
// This demonstrates how to integrate with secure hardware that doesn't expose private keys.
type SimulatedHSM struct {
	mu      sync.RWMutex
	keys    map[string]*rsa.PrivateKey // keyHandle -> privateKey
	nextID  int
	keySize int
}

// NewSimulatedHSM creates a new simulated HSM.
func NewSimulatedHSM(keySize int) *SimulatedHSM {
	return &SimulatedHSM{
		keys:    make(map[string]*rsa.PrivateKey),
		keySize: keySize,
	}
}

// hsmPrivateKeyHandle represents a handle to a key stored in the HSM.
// The actual private key never leaves the HSM - only this handle is exposed.
type hsmPrivateKeyHandle struct {
	hsm       *SimulatedHSM
	keyHandle string
	publicKey []byte // Public key can be exported
}

// GenerateKey generates a new key pair inside the HSM.
// Returns a key reference (for DerivePub) and public key bytes.
func (h *SimulatedHSM) GenerateKey() (skRef []byte, ek []byte, err error) {
	// Generate key inside HSM
	privateKey, err := rsa.GenerateKey(rand.Reader, h.keySize)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate RSA key: %w", err)
	}

	// Store key in HSM with unique handle
	h.mu.Lock()
	keyHandle := fmt.Sprintf("hsm-key-%d", h.nextID)
	h.nextID++
	h.keys[keyHandle] = privateKey
	h.mu.Unlock()

	// Export public key
	publicKey := &privateKey.PublicKey
	ekBytes, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to marshal public key: %w", err)
	}

	// skRef is the key handle (not the actual private key)
	skRef = []byte(keyHandle)

	return skRef, ekBytes, nil
}

// Decapsulate performs decapsulation inside the HSM using the key handle.
// The private key never leaves the HSM.
func (h *SimulatedHSM) Decapsulate(keyHandle string, ciphertext []byte) ([]byte, error) {
	h.mu.RLock()
	privateKey, ok := h.keys[keyHandle]
	h.mu.RUnlock()

	if !ok {
		return nil, errors.New("key handle not found in HSM")
	}

	// Perform decryption inside HSM
	plaintext, err := rsa.DecryptOAEP(sha256.New(), rand.Reader, privateKey, ciphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("HSM decapsulation failed: %w", err)
	}

	return plaintext, nil
}

// GetPublicKey retrieves the public key for a given key handle.
func (h *SimulatedHSM) GetPublicKey(keyHandle string) ([]byte, error) {
	h.mu.RLock()
	privateKey, ok := h.keys[keyHandle]
	h.mu.RUnlock()

	if !ok {
		return nil, errors.New("key handle not found in HSM")
	}

	publicKey := &privateKey.PublicKey
	return x509.MarshalPKIXPublicKey(publicKey)
}

// HSMKEM is a KEM implementation that uses a simulated HSM.
// This demonstrates how to integrate PVE with hardware security modules.
type HSMKEM struct {
	hsm *SimulatedHSM
}

// NewHSMKEM creates a new HSM-based KEM.
func NewHSMKEM(keySize int) *HSMKEM {
	return &HSMKEM{
		hsm: NewSimulatedHSM(keySize),
	}
}

// Generate generates a key pair using the HSM.
func (k *HSMKEM) Generate() (skRef []byte, ek []byte, err error) {
	return k.hsm.GenerateKey()
}

// Encapsulate performs KEM encapsulation.
func (k *HSMKEM) Encapsulate(ek []byte, rho [32]byte) (ct, ss []byte, err error) {
	// Parse public key
	pubKeyInterface, err := x509.ParsePKIXPublicKey(ek)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to parse public key: %w", err)
	}

	publicKey, ok := pubKeyInterface.(*rsa.PublicKey)
	if !ok {
		return nil, nil, errors.New("not an RSA public key")
	}

	// Use rho as the shared secret (deterministic)
	ss = make([]byte, 32)
	copy(ss, rho[:])

	// Encrypt shared secret with public key using deterministic randomness
	deterministicRand := newDeterministicReader(rho[:])
	ct, err = rsa.EncryptOAEP(sha256.New(), deterministicRand, publicKey, ss, nil)
	if err != nil {
		return nil, nil, fmt.Errorf("encapsulation failed: %w", err)
	}

	return ct, ss, nil
}

// Decapsulate performs KEM decapsulation using the HSM.
// The skHandle must be a *hsmPrivateKeyHandle.
func (k *HSMKEM) Decapsulate(skHandle any, ct []byte) (ss []byte, err error) {
	handle, ok := skHandle.(*hsmPrivateKeyHandle)
	if !ok {
		return nil, errors.New("invalid handle type: expected *hsmPrivateKeyHandle")
	}

	// Delegate to HSM - private key never leaves the HSM
	return handle.hsm.Decapsulate(handle.keyHandle, ct)
}

// DerivePub derives the public key from a private key reference (key handle).
func (k *HSMKEM) DerivePub(skRef []byte) ([]byte, error) {
	keyHandle := string(skRef)
	return k.hsm.GetPublicKey(keyHandle)
}

// NewPrivateKeyHandle creates a handle to a key stored in the HSM.
func (k *HSMKEM) NewPrivateKeyHandle(skRef []byte) (any, error) {
	keyHandle := string(skRef)

	// Verify the key exists in the HSM
	publicKey, err := k.hsm.GetPublicKey(keyHandle)
	if err != nil {
		return nil, err
	}

	return &hsmPrivateKeyHandle{
		hsm:       k.hsm,
		keyHandle: keyHandle,
		publicKey: publicKey,
	}, nil
}

// FreePrivateKeyHandle is a no-op for HSM handles.
func (k *HSMKEM) FreePrivateKeyHandle(handle any) error {
	// HSM manages its own keys
	return nil
}
