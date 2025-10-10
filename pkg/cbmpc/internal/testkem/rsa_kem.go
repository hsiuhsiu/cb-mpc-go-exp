// Package testkem provides KEM implementations for testing purposes.
package testkem

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"errors"
	"io"
)

// ToyRSAKEM implements a simple RSA-based KEM for testing.
// WARNING: This is a toy implementation for testing only. Do not use in production.
type ToyRSAKEM struct {
	keySize int // RSA key size in bits
}

// NewToyRSAKEM creates a new ToyRSAKEM with the specified key size.
// Typical test values: 2048, 3072, or 4096 bits.
func NewToyRSAKEM(keySize int) *ToyRSAKEM {
	return &ToyRSAKEM{
		keySize: keySize,
	}
}

// privateKeyHandle wraps an RSA private key for use as an opaque handle.
type privateKeyHandle struct {
	key   *rsa.PrivateKey
	skRef []byte // Serialized reference
}

// Generate generates a new RSA key pair.
// Returns (skRef, ek, error) where:
// - skRef is a serialized reference to the private key (can be stored/transmitted)
// - ek is the serialized public key
func (k *ToyRSAKEM) Generate() (skRef, ek []byte, err error) {
	// Generate RSA key pair
	privKey, err := rsa.GenerateKey(rand.Reader, k.keySize)
	if err != nil {
		return nil, nil, err
	}

	// Serialize private key to PKCS#8
	skRef, err = x509.MarshalPKCS8PrivateKey(privKey)
	if err != nil {
		return nil, nil, err
	}

	// Serialize public key to PKIX
	ek, err = x509.MarshalPKIXPublicKey(&privKey.PublicKey)
	if err != nil {
		return nil, nil, err
	}

	return skRef, ek, nil
}

// Encapsulate generates a ciphertext and shared secret for the given public key.
// rho is used as a deterministic random seed for testing.
func (k *ToyRSAKEM) Encapsulate(ek []byte, rho [32]byte) (ct, ss []byte, err error) {
	// Parse public key
	pubKeyIface, err := x509.ParsePKIXPublicKey(ek)
	if err != nil {
		return nil, nil, err
	}

	pubKey, ok := pubKeyIface.(*rsa.PublicKey)
	if !ok {
		return nil, nil, errors.New("not an RSA public key")
	}

	// Use rho as the shared secret (deterministic for testing)
	// In a real KEM, this would be a randomly generated value
	ss = make([]byte, 32)
	copy(ss, rho[:])

	// Create a deterministic random source from rho for RSA-OAEP padding
	// This ensures the encryption is deterministic given the same rho
	// We extend rho by repeatedly hashing it to create enough random bytes
	deterministicRand := newDeterministicReader(rho[:])

	// Encrypt the shared secret using RSA-OAEP with deterministic randomness
	ct, err = rsa.EncryptOAEP(sha256.New(), deterministicRand, pubKey, ss, nil)
	if err != nil {
		return nil, nil, err
	}

	return ct, ss, nil
}

// Decapsulate recovers the shared secret from a ciphertext using the private key.
// skHandle is a Go object (type any) containing the private key handle.
// The bindings layer handles CGO safety automatically.
func (k *ToyRSAKEM) Decapsulate(skHandle any, ct []byte) (ss []byte, err error) {
	if skHandle == nil {
		return nil, errors.New("nil private key handle")
	}

	// Cast to the actual handle type
	handle, ok := skHandle.(*privateKeyHandle)
	if !ok {
		return nil, errors.New("invalid handle type")
	}

	// Decrypt the ciphertext using RSA-OAEP
	ss, err = rsa.DecryptOAEP(sha256.New(), rand.Reader, handle.key, ct, nil)
	if err != nil {
		return nil, err
	}

	return ss, nil
}

// DerivePub derives the public key from a private key reference.
func (k *ToyRSAKEM) DerivePub(skRef []byte) ([]byte, error) {
	// Parse private key
	privKeyIface, err := x509.ParsePKCS8PrivateKey(skRef)
	if err != nil {
		return nil, err
	}

	privKey, ok := privKeyIface.(*rsa.PrivateKey)
	if !ok {
		return nil, errors.New("not an RSA private key")
	}

	// Serialize public key to PKIX
	ek, err := x509.MarshalPKIXPublicKey(&privKey.PublicKey)
	if err != nil {
		return nil, err
	}

	return ek, nil
}

// NewPrivateKeyHandle creates a private key handle from a private key reference.
// This is used for testing to create the handle expected by Decapsulate.
// Returns a Go object (any) that can be passed directly to Decapsulate.
// The bindings layer handles CGO safety automatically when passing through C.
func (k *ToyRSAKEM) NewPrivateKeyHandle(skRef []byte) (any, error) {
	// Parse private key
	privKeyIface, err := x509.ParsePKCS8PrivateKey(skRef)
	if err != nil {
		return nil, err
	}

	privKey, ok := privKeyIface.(*rsa.PrivateKey)
	if !ok {
		return nil, errors.New("not an RSA private key")
	}

	handle := &privateKeyHandle{
		key:   privKey,
		skRef: skRef,
	}

	// Return the handle directly - the bindings layer will register it
	return handle, nil
}

// FreePrivateKeyHandle releases resources associated with a private key handle.
// This should be called when the handle is no longer needed.
// With the transparent handle registry, this is now a no-op as the bindings
// layer manages the lifecycle.
func (k *ToyRSAKEM) FreePrivateKeyHandle(handle any) {
	// No-op: The bindings layer's handle registry manages the lifecycle
	// This method is kept for API compatibility with existing tests
}

// deterministicReader provides a deterministic random stream from a seed.
// It extends the seed by repeatedly hashing it.
type deterministicReader struct {
	buffer  *bytes.Reader
	seed    []byte
	counter int
}

// newDeterministicReader creates a deterministic reader from a seed.
func newDeterministicReader(seed []byte) io.Reader {
	// Generate initial buffer by hashing seed multiple times
	var buf bytes.Buffer
	for i := 0; i < 32; i++ { // Generate enough bytes for RSA-OAEP
		h := sha256.New()
		h.Write(seed)
		h.Write([]byte{byte(i)})
		buf.Write(h.Sum(nil))
	}
	return &deterministicReader{
		buffer:  bytes.NewReader(buf.Bytes()),
		seed:    seed,
		counter: 32,
	}
}

func (d *deterministicReader) Read(p []byte) (n int, err error) {
	n, err = d.buffer.Read(p)
	if err == io.EOF && n < len(p) {
		// Extend buffer by hashing more
		var buf bytes.Buffer
		for i := 0; i < 32; i++ {
			h := sha256.New()
			h.Write(d.seed)
			h.Write([]byte{byte(d.counter + i)})
			buf.Write(h.Sum(nil))
		}
		d.counter += 32
		d.buffer = bytes.NewReader(buf.Bytes())

		// Read remaining bytes
		n2, err2 := d.buffer.Read(p[n:])
		return n + n2, err2
	}
	return n, err
}
