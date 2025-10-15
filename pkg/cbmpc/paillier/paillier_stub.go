//go:build !cgo || windows

package paillier

import "github.com/coinbase/cb-mpc-go/pkg/cbmpc/internal/backend"

// Paillier represents a Paillier cryptosystem instance (stub for non-CGO builds).
type Paillier struct{}

// Generate is a stub that returns ErrNotBuilt.
func Generate() (*Paillier, error) {
	return nil, backend.ErrNotBuilt
}

// FromPublicKey is a stub that returns ErrNotBuilt.
func FromPublicKey([]byte) (*Paillier, error) {
	return nil, backend.ErrNotBuilt
}

// FromPrivateKey is a stub that returns ErrNotBuilt.
func FromPrivateKey([]byte, []byte, []byte) (*Paillier, error) {
	return nil, backend.ErrNotBuilt
}

// Close is a no-op stub.
func (p *Paillier) Close() {}

// HasPrivateKey is a stub that returns false.
func (p *Paillier) HasPrivateKey() bool {
	return false
}

// GetN is a stub that returns ErrNotBuilt.
func (p *Paillier) GetN() ([]byte, error) {
	return nil, backend.ErrNotBuilt
}

// Encrypt is a stub that returns ErrNotBuilt.
func (p *Paillier) Encrypt([]byte) ([]byte, error) {
	return nil, backend.ErrNotBuilt
}

// Decrypt is a stub that returns ErrNotBuilt.
func (p *Paillier) Decrypt([]byte) ([]byte, error) {
	return nil, backend.ErrNotBuilt
}

// AddCiphers is a stub that returns ErrNotBuilt.
func (p *Paillier) AddCiphers([]byte, []byte) ([]byte, error) {
	return nil, backend.ErrNotBuilt
}

// MulScalar is a stub that returns ErrNotBuilt.
func (p *Paillier) MulScalar([]byte, []byte) ([]byte, error) {
	return nil, backend.ErrNotBuilt
}

// VerifyCipher is a stub that returns ErrNotBuilt.
func (p *Paillier) VerifyCipher([]byte) error {
	return backend.ErrNotBuilt
}

// Serialize is a stub that returns ErrNotBuilt.
func (p *Paillier) Serialize() ([]byte, error) {
	return nil, backend.ErrNotBuilt
}

// Deserialize is a stub that returns ErrNotBuilt.
func Deserialize([]byte) (*Paillier, error) {
	return nil, backend.ErrNotBuilt
}

// Handle is a stub that returns nil.
func (p *Paillier) Handle() backend.Paillier {
	return nil
}
