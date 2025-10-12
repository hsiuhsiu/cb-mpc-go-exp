//go:build cgo && !windows

package rsa

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"errors"
	"fmt"
	"runtime"
	"sync"
)

// KEM is a production-grade RSA-based Key Encapsulation Mechanism.
// It uses RSA-OAEP with SHA-256 for secure key encapsulation.
//
// Security considerations:
//   - Minimum recommended key size is 2048 bits
//   - 3072 bits recommended for long-term security (post-2030)
//   - 4096 bits for high-security applications
//   - Uses RSA-OAEP with SHA-256 hash function
//   - Private keys are held in DER form in memory and zeroized on free
//
// This KEM is suitable for production use with PVE encryption.
type KEM struct {
	keySize int
}

// New creates a new production-grade RSA KEM.
// Recommended key sizes:
//   - 2048: Minimum for current use
//   - 3072: Recommended for long-term security
//   - 4096: High security applications
func New(keySize int) (*KEM, error) {
	if keySize < 2048 {
		return nil, errors.New("key size must be at least 2048 bits")
	}
	if keySize%1024 != 0 {
		return nil, errors.New("key size must be a multiple of 1024")
	}
	return &KEM{keySize: keySize}, nil
}

// privateKeyHandle represents a handle to an RSA private key.
// The private key is stored in DER format for security.
type privateKeyHandle struct {
	mu        sync.RWMutex
	keyDER    []byte // PKCS#8 DER encoding
	publicKey []byte // PKIX DER encoding
}

// Generate generates a new RSA key pair.
// Returns:
//   - skRef: Private key reference (PKCS#8 DER format)
//   - ek: Public key (PKIX DER format)
//   - err: Any error that occurred
func (k *KEM) Generate() (skRef []byte, ek []byte, err error) {
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
func (k *KEM) Encapsulate(ek []byte, rho [32]byte) (ct, ss []byte, err error) {
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
//   - skHandle: Private key handle (must be *privateKeyHandle)
//   - ct: Ciphertext to decrypt
//
// Returns:
//   - ss: Shared secret (32 bytes)
//   - err: Any error that occurred
func (k *KEM) Decapsulate(skHandle any, ct []byte) (ss []byte, err error) {
	handle, ok := skHandle.(*privateKeyHandle)
	if !ok {
		return nil, errors.New("invalid handle type: expected *privateKeyHandle")
	}

	// Parse private key from DER
	handle.mu.RLock()
	keyDER := make([]byte, len(handle.keyDER))
	copy(keyDER, handle.keyDER)
	handle.mu.RUnlock()

	keyInterface, err := x509.ParsePKCS8PrivateKey(keyDER)
	if err != nil {
		zeroizeBytes(keyDER)
		return nil, fmt.Errorf("failed to parse private key: %w", err)
	}

	privateKey, ok := keyInterface.(*rsa.PrivateKey)
	if !ok {
		zeroizeBytes(keyDER)
		return nil, errors.New("not an RSA private key")
	}

	// Decrypt ciphertext with RSA-OAEP
	ss, err = rsa.DecryptOAEP(sha256.New(), rand.Reader, privateKey, ct, nil)

	// Zeroize sensitive data
	zeroizeBytes(keyDER)
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
func (k *KEM) DerivePub(skRef []byte) ([]byte, error) {
	// Parse private key
	keyInterface, err := x509.ParsePKCS8PrivateKey(skRef)
	if err != nil {
		return nil, fmt.Errorf("failed to parse private key: %w", err)
	}

	privateKey, ok := keyInterface.(*rsa.PrivateKey)
	if !ok {
		return nil, errors.New("not an RSA private key")
	}

	// Validate key size
	if privateKey.Size() < 256 { // 2048 bits minimum
		return nil, fmt.Errorf("private key too small: %d bytes (minimum 256 bytes)", privateKey.Size())
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
func (k *KEM) NewPrivateKeyHandle(skRef []byte) (any, error) {
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
	handle := &privateKeyHandle{
		keyDER:    make([]byte, len(skRef)),
		publicKey: publicKey,
	}
	copy(handle.keyDER, skRef)

	return handle, nil
}

// FreePrivateKeyHandle securely frees a private key handle.
// This zeroizes the private key material from memory.
func (k *KEM) FreePrivateKeyHandle(handle any) error {
	h, ok := handle.(*privateKeyHandle)
	if !ok {
		return errors.New("invalid handle type: expected *privateKeyHandle")
	}

	// Zeroize private key material
	h.mu.Lock()
	zeroizeBytes(h.keyDER)
	h.keyDER = nil
	h.publicKey = nil
	h.mu.Unlock()

	return nil
}

// zeroizeBytes overwrites the provided slice with zeros and prevents compiler
// dead store elimination using runtime.KeepAlive.
func zeroizeBytes(buf []byte) {
	for i := range buf {
		buf[i] = 0
	}
	// Prevent dead store elimination per golang/go#33325
	runtime.KeepAlive(buf)
}

// deterministicReader generates deterministic bytes from a 32-byte seed using
// HKDF-HMAC-SHA256 (Extract+Expand) with fixed context strings. It is used
// solely to make RSA-OAEP encryption deterministic for PVE; it is not a
// general-purpose RNG. The Read method always fills the provided buffer.
type deterministicReader struct {
	// seed is the 32-byte deterministic seed (rho)
	seed []byte
	// prk is the HKDF-Extract output (initialized on first use)
	prk []byte
	// lastBlock stores T(i) from HKDF-Expand
	lastBlock []byte
	// counter is the HKDF-Expand block counter (1..255)
	counter byte
	// cache holds leftover bytes from the last generated block
	cache []byte
	// init indicates whether prk has been derived
	init bool
}

func (r *deterministicReader) Read(p []byte) (int, error) {
	// One-time initialization: HKDF-Extract with fixed salt and seed as IKM
	if !r.init {
		// Fixed context-specific salt; not secret, binds generator to purpose
		const salt = "cbmpc-pve-rsa-oaep-hkdf"
		mac := hmac.New(sha256.New, []byte(salt))
		mac.Write(r.seed)
		r.prk = mac.Sum(nil) // 32 bytes for SHA-256
		r.lastBlock = nil
		r.counter = 0
		r.cache = nil
		r.init = true
	}

	out := 0

	// First, drain any cached leftover bytes
	if len(r.cache) > 0 {
		c := copy(p[out:], r.cache)
		out += c
		r.cache = r.cache[c:]
	}

	// Generate blocks until p is fully filled
	for out < len(p) {
		// HKDF-Expand step: T(i) = HMAC(PRK, T(i-1) || info || i)
		// Use fixed info to scope usage
		const info = "cbmpc-pve-rsa-oaep"
		h := hmac.New(sha256.New, r.prk)
		if len(r.lastBlock) > 0 {
			h.Write(r.lastBlock)
		}
		h.Write([]byte(info))
		// Increment counter (wrap at 255 to 1; more than 255 blocks is unrealistic here)
		if r.counter == 255 {
			r.counter = 0
		}
		r.counter++
		h.Write([]byte{r.counter})
		block := h.Sum(nil) // 32-byte block
		r.lastBlock = block

		// Copy into output; keep leftovers in cache
		n := copy(p[out:], block)
		out += n
		if n < len(block) {
			r.cache = block[n:]
		}
	}

	return out, nil
}
