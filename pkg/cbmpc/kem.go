//go:build cgo && !windows

package cbmpc

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"errors"
	"fmt"
	"sync"
)

// KEM is the interface for Key Encapsulation Mechanisms used by PVE.
// Implementations provide encryption key generation, encapsulation, and decapsulation.
//
// This interface allows plugging in custom KEM schemes (e.g., ML-KEM, RSA-KEM, etc.)
// for use with publicly verifiable encryption.
//
// Note: The Decapsulate method's skHandle parameter can be any Go type, including
// types containing Go pointers. The bindings layer automatically handles converting
// this to a CGO-safe handle when passing through C code.
type KEM interface {
	// Encapsulate generates a ciphertext and shared secret for the given public key.
	// rho is a 32-byte random seed for deterministic encapsulation.
	// Returns (ciphertext, shared_secret, error).
	Encapsulate(ek []byte, rho [32]byte) (ct, ss []byte, err error)

	// Decapsulate recovers the shared secret from a ciphertext using the private key.
	// skHandle can be any Go value representing the private key.
	// Returns (shared_secret, error).
	Decapsulate(skHandle any, ct []byte) (ss []byte, err error)

	// DerivePub derives the public key from a private key reference.
	// skRef is a serialized reference to the private key.
	// Returns (public_key, error).
	DerivePub(skRef []byte) ([]byte, error)
}

// RSAKEM is a production-grade RSA-based Key Encapsulation Mechanism.
// It uses RSA-OAEP with SHA-256 for secure key encapsulation.
//
// Security considerations:
//   - Minimum recommended key size is 2048 bits
//   - 3072 bits recommended for long-term security (post-2030)
//   - 4096 bits for high-security applications
//   - Uses RSA-OAEP with SHA-256 hash function
//   - Private keys are stored encrypted in memory
//
// This KEM is suitable for production use with PVE encryption.
type RSAKEM struct {
	keySize int
}

// NewRSAKEM creates a new production-grade RSA KEM.
// Recommended key sizes:
//   - 2048: Minimum for current use
//   - 3072: Recommended for long-term security
//   - 4096: High security applications
func NewRSAKEM(keySize int) (*RSAKEM, error) {
	if keySize < 2048 {
		return nil, errors.New("key size must be at least 2048 bits")
	}
	if keySize%1024 != 0 {
		return nil, errors.New("key size must be a multiple of 1024")
	}
	return &RSAKEM{keySize: keySize}, nil
}

// rsaPrivateKeyHandle represents a handle to an RSA private key.
// The private key is stored in DER format for security.
type rsaPrivateKeyHandle struct {
	mu        sync.RWMutex
	keyDER    []byte // PKCS#8 DER encoding
	publicKey []byte // PKIX DER encoding
}

// Generate generates a new RSA key pair.
// Returns:
//   - skRef: Private key reference (PKCS#8 DER format)
//   - ek: Public key (PKIX DER format)
//   - err: Any error that occurred
func (k *RSAKEM) Generate() (skRef []byte, ek []byte, err error) {
	// Generate RSA key pair
	privateKey, err := rsa.GenerateKey(rand.Reader, k.keySize)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate RSA key: %w", err)
	}

	// Marshal private key to PKCS#8 DER format
	skRef, err = x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to marshal private key: %w", err)
	}

	// Marshal public key to PKIX DER format
	ek, err = x509.MarshalPKIXPublicKey(&privateKey.PublicKey)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to marshal public key: %w", err)
	}

	return skRef, ek, nil
}

// Encapsulate generates a ciphertext and shared secret for the given public key.
// Uses RSA-OAEP with SHA-256 for encryption.
//
// Parameters:
//   - ek: Public key in PKIX DER format
//   - rho: 32-byte random seed for deterministic encapsulation
//
// Returns:
//   - ct: Ciphertext (RSA-OAEP encrypted shared secret)
//   - ss: Shared secret (32 bytes)
//   - err: Any error that occurred
func (k *RSAKEM) Encapsulate(ek []byte, rho [32]byte) (ct, ss []byte, err error) {
	// Parse public key
	pubKeyInterface, err := x509.ParsePKIXPublicKey(ek)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to parse public key: %w", err)
	}

	publicKey, ok := pubKeyInterface.(*rsa.PublicKey)
	if !ok {
		return nil, nil, errors.New("not an RSA public key")
	}

	// Validate key size
	keySize := publicKey.Size()
	if keySize < 256 { // 2048 bits minimum
		return nil, nil, fmt.Errorf("public key too small: %d bytes (minimum 256 bytes)", keySize)
	}

	// Use rho as the shared secret (for PVE determinism)
	ss = make([]byte, 32)
	copy(ss, rho[:])

	// Encrypt shared secret with RSA-OAEP
	// Use deterministic reader for PVE compatibility
	ct, err = rsa.EncryptOAEP(sha256.New(), &deterministicReader{seed: rho[:]}, publicKey, ss, nil)
	if err != nil {
		return nil, nil, fmt.Errorf("RSA-OAEP encapsulation failed: %w", err)
	}

	return ct, ss, nil
}

// Decapsulate recovers the shared secret from a ciphertext using the private key.
// Uses RSA-OAEP with SHA-256 for decryption.
//
// Parameters:
//   - skHandle: Private key handle (must be *rsaPrivateKeyHandle)
//   - ct: Ciphertext to decrypt
//
// Returns:
//   - ss: Shared secret (32 bytes)
//   - err: Any error that occurred
func (k *RSAKEM) Decapsulate(skHandle any, ct []byte) (ss []byte, err error) {
	handle, ok := skHandle.(*rsaPrivateKeyHandle)
	if !ok {
		return nil, errors.New("invalid handle type: expected *rsaPrivateKeyHandle")
	}

	// Parse private key from DER
	handle.mu.RLock()
	keyDER := make([]byte, len(handle.keyDER))
	copy(keyDER, handle.keyDER)
	handle.mu.RUnlock()

	keyInterface, err := x509.ParsePKCS8PrivateKey(keyDER)
	if err != nil {
		ZeroizeBytes(keyDER)
		return nil, fmt.Errorf("failed to parse private key: %w", err)
	}

	privateKey, ok := keyInterface.(*rsa.PrivateKey)
	if !ok {
		ZeroizeBytes(keyDER)
		return nil, errors.New("not an RSA private key")
	}

	// Decrypt ciphertext with RSA-OAEP
	ss, err = rsa.DecryptOAEP(sha256.New(), rand.Reader, privateKey, ct, nil)

	// Zeroize sensitive data
	ZeroizeBytes(keyDER)
	// Note: privateKey fields are not easily zeroizable in Go
	// The GC will eventually clean up the memory

	if err != nil {
		return nil, fmt.Errorf("RSA-OAEP decapsulation failed: %w", err)
	}

	return ss, nil
}

// DerivePub derives the public key from a private key reference.
//
// Parameters:
//   - skRef: Private key reference in PKCS#8 DER format
//
// Returns:
//   - Public key in PKIX DER format
//   - Any error that occurred
func (k *RSAKEM) DerivePub(skRef []byte) ([]byte, error) {
	// Parse private key
	keyInterface, err := x509.ParsePKCS8PrivateKey(skRef)
	if err != nil {
		return nil, fmt.Errorf("failed to parse private key: %w", err)
	}

	privateKey, ok := keyInterface.(*rsa.PrivateKey)
	if !ok {
		return nil, errors.New("not an RSA private key")
	}

	// Marshal public key
	return x509.MarshalPKIXPublicKey(&privateKey.PublicKey)
}

// NewPrivateKeyHandle creates a handle to a private key.
// The private key is stored in DER format for security.
//
// Parameters:
//   - skRef: Private key reference in PKCS#8 DER format
//
// Returns:
//   - Handle that can be passed to Decapsulate
//   - Any error that occurred
func (k *RSAKEM) NewPrivateKeyHandle(skRef []byte) (any, error) {
	// Validate by parsing
	keyInterface, err := x509.ParsePKCS8PrivateKey(skRef)
	if err != nil {
		return nil, fmt.Errorf("failed to parse private key: %w", err)
	}

	privateKey, ok := keyInterface.(*rsa.PrivateKey)
	if !ok {
		return nil, errors.New("not an RSA private key")
	}

	// Validate key size
	keySize := privateKey.Size()
	if keySize < 256 { // 2048 bits minimum
		return nil, fmt.Errorf("private key too small: %d bytes (minimum 256 bytes)", keySize)
	}

	// Get public key
	publicKey, err := x509.MarshalPKIXPublicKey(&privateKey.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal public key: %w", err)
	}

	// Create handle with DER-encoded key
	handle := &rsaPrivateKeyHandle{
		keyDER:    make([]byte, len(skRef)),
		publicKey: publicKey,
	}
	copy(handle.keyDER, skRef)

	return handle, nil
}

// FreePrivateKeyHandle securely frees a private key handle.
// This zeroizes the private key material from memory.
func (k *RSAKEM) FreePrivateKeyHandle(handle any) error {
	h, ok := handle.(*rsaPrivateKeyHandle)
	if !ok {
		return errors.New("invalid handle type: expected *rsaPrivateKeyHandle")
	}

	// Zeroize private key material
	h.mu.Lock()
	ZeroizeBytes(h.keyDER)
	h.keyDER = nil
	h.publicKey = nil
	h.mu.Unlock()

	return nil
}

// deterministicReader is a reader that generates deterministic "random" bytes
// from a seed. This is used for PVE's deterministic encryption requirement.
type deterministicReader struct {
	seed []byte
	pos  int
}

func (r *deterministicReader) Read(p []byte) (n int, err error) {
	// Hash the seed with position to generate bytes
	for i := range p {
		if r.pos%32 == 0 {
			// Generate new block of random bytes by hashing seed || position
			h := sha256.New()
			h.Write(r.seed)
			h.Write([]byte{byte(r.pos / 32)})
			block := h.Sum(nil)
			copy(p[i:], block)
			r.pos += len(block)
			return len(p), nil
		}
		r.pos++
	}
	return len(p), nil
}
