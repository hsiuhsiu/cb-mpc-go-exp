//go:build cgo && !windows

package paillier

import (
	"errors"
	"runtime"

	"github.com/coinbase/cb-mpc-go/pkg/cbmpc"
	"github.com/coinbase/cb-mpc-go/pkg/cbmpc/internal/backend"
)

// Paillier represents a Paillier cryptosystem instance (public or private key).
// The key is stored as an opaque C++ object handle.
//
// A Paillier instance can be created in three ways:
//   - Generate(): Creates a new keypair (has both public and private key)
//   - FromPublicKey(): Creates from modulus N only (public key only, can encrypt/verify)
//   - FromPrivateKey(): Creates from N, p, q (has private key, can decrypt)
//
// Memory management: Call Close() when done, or rely on finalizer for cleanup.
type Paillier struct {
	handle backend.Paillier
}

// Generate creates a new Paillier keypair with a 2048-bit modulus.
// See cb-mpc/src/cbmpc/crypto/base_paillier.h for implementation details.
func Generate() (*Paillier, error) {
	handle, err := backend.PaillierGenerate()
	if err != nil {
		return nil, cbmpc.RemapError(err)
	}

	p := &Paillier{handle: handle}
	runtime.SetFinalizer(p, (*Paillier).Close)
	return p, nil
}

// FromPublicKey creates a Paillier instance from a public key (modulus n).
// The returned instance can encrypt and verify ciphertexts but cannot decrypt.
// See cb-mpc/src/cbmpc/crypto/base_paillier.h for implementation details.
func FromPublicKey(n []byte) (*Paillier, error) {
	handle, err := backend.PaillierCreatePub(n)
	if err != nil {
		return nil, cbmpc.RemapError(err)
	}

	p := &Paillier{handle: handle}
	runtime.SetFinalizer(p, (*Paillier).Close)
	return p, nil
}

// FromPrivateKey creates a Paillier instance from a private key (n, p, q).
// The returned instance can perform all operations including decryption.
// See cb-mpc/src/cbmpc/crypto/base_paillier.h for implementation details.
func FromPrivateKey(n, p, q []byte) (*Paillier, error) {
	handle, err := backend.PaillierCreatePrv(n, p, q)
	if err != nil {
		return nil, cbmpc.RemapError(err)
	}

	paillier := &Paillier{handle: handle}
	runtime.SetFinalizer(paillier, (*Paillier).Close)
	return paillier, nil
}

// Close frees the underlying C++ Paillier object.
// After calling Close, the Paillier instance must not be used.
func (p *Paillier) Close() {
	if p.handle != nil {
		backend.PaillierFree(p.handle)
		p.handle = nil
		runtime.SetFinalizer(p, nil)
	}
}

// HasPrivateKey returns true if this Paillier instance has a private key.
func (p *Paillier) HasPrivateKey() bool {
	if p.handle == nil {
		return false
	}
	return backend.PaillierHasPrivateKey(p.handle)
}

// GetN returns the modulus N of the Paillier key.
func (p *Paillier) GetN() ([]byte, error) {
	if p.handle == nil {
		return nil, errors.New("nil or closed paillier")
	}
	n, err := backend.PaillierGetN(p.handle)
	if err != nil {
		return nil, cbmpc.RemapError(err)
	}
	runtime.KeepAlive(p)
	return n, nil
}

// Encrypt encrypts a plaintext value using the Paillier cryptosystem.
// The plaintext must be less than the modulus N.
// See cb-mpc/src/cbmpc/crypto/base_paillier.h for implementation details.
func (p *Paillier) Encrypt(plaintext []byte) ([]byte, error) {
	if p.handle == nil {
		return nil, errors.New("nil or closed paillier")
	}
	ciphertext, err := backend.PaillierEncrypt(p.handle, plaintext)
	if err != nil {
		return nil, cbmpc.RemapError(err)
	}
	runtime.KeepAlive(p)
	return ciphertext, nil
}

// Decrypt decrypts a ciphertext value using the Paillier cryptosystem.
// Requires a private key (HasPrivateKey() must return true).
// See cb-mpc/src/cbmpc/crypto/base_paillier.h for implementation details.
func (p *Paillier) Decrypt(ciphertext []byte) ([]byte, error) {
	if p.handle == nil {
		return nil, errors.New("nil or closed paillier")
	}
	plaintext, err := backend.PaillierDecrypt(p.handle, ciphertext)
	if err != nil {
		return nil, cbmpc.RemapError(err)
	}
	runtime.KeepAlive(p)
	return plaintext, nil
}

// AddCiphers homomorphically adds two Paillier ciphertexts.
// Result decrypts to plaintext1 + plaintext2 (mod N).
// See cb-mpc/src/cbmpc/crypto/base_paillier.h for implementation details.
func (p *Paillier) AddCiphers(c1, c2 []byte) ([]byte, error) {
	if p.handle == nil {
		return nil, errors.New("nil or closed paillier")
	}
	result, err := backend.PaillierAddCiphers(p.handle, c1, c2)
	if err != nil {
		return nil, cbmpc.RemapError(err)
	}
	runtime.KeepAlive(p)
	return result, nil
}

// MulScalar homomorphically multiplies a Paillier ciphertext by a scalar.
// Result decrypts to plaintext * scalar (mod N).
// See cb-mpc/src/cbmpc/crypto/base_paillier.h for implementation details.
func (p *Paillier) MulScalar(ciphertext, scalar []byte) ([]byte, error) {
	if p.handle == nil {
		return nil, errors.New("nil or closed paillier")
	}
	result, err := backend.PaillierMulScalar(p.handle, ciphertext, scalar)
	if err != nil {
		return nil, cbmpc.RemapError(err)
	}
	runtime.KeepAlive(p)
	return result, nil
}

// VerifyCipher verifies that a ciphertext is well-formed for this Paillier instance.
// Checks that the ciphertext is in the valid range for this modulus.
// See cb-mpc/src/cbmpc/crypto/base_paillier.h for implementation details.
func (p *Paillier) VerifyCipher(ciphertext []byte) error {
	if p.handle == nil {
		return errors.New("nil or closed paillier")
	}
	err := backend.PaillierVerifyCipher(p.handle, ciphertext)
	if err != nil {
		return cbmpc.RemapError(err)
	}
	runtime.KeepAlive(p)
	return nil
}

// Serialize serializes the Paillier instance to bytes for storage or transmission.
// The serialized form includes the public key (N) and private key (p, q) if present.
// See cb-mpc/src/cbmpc/crypto/base_paillier.h for implementation details.
func (p *Paillier) Serialize() ([]byte, error) {
	if p.handle == nil {
		return nil, errors.New("nil or closed paillier")
	}
	data, err := backend.PaillierSerialize(p.handle)
	if err != nil {
		return nil, cbmpc.RemapError(err)
	}
	runtime.KeepAlive(p)
	return data, nil
}

// Deserialize deserializes a Paillier instance from bytes.
// See cb-mpc/src/cbmpc/crypto/base_paillier.h for implementation details.
func Deserialize(data []byte) (*Paillier, error) {
	handle, err := backend.PaillierDeserialize(data)
	if err != nil {
		return nil, cbmpc.RemapError(err)
	}

	p := &Paillier{handle: handle}
	runtime.SetFinalizer(p, (*Paillier).Close)
	return p, nil
}

// Handle returns the internal backend handle for use with ZK proofs.
// This is an internal method used by the zk package.
func (p *Paillier) Handle() backend.Paillier {
	return p.handle
}
