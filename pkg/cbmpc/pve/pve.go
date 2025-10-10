package pve

import (
	"context"
	"errors"
	"runtime"

	"github.com/coinbase/cb-mpc-go/internal/bindings"
	"github.com/coinbase/cb-mpc-go/pkg/cbmpc"
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

// PVE represents a Publicly Verifiable Encryption instance with a specific KEM.
// Multiple PVE instances can coexist with different KEMs.
type PVE struct {
	kem KEM
}

// New creates a new PVE instance with the specified KEM.
// See cb-mpc/src/cbmpc/protocol/pve.h for protocol details.
func New(kem KEM) (*PVE, error) {
	if kem == nil {
		return nil, errors.New("nil KEM")
	}
	return &PVE{kem: kem}, nil
}

// Ciphertext represents a publicly verifiable encryption ciphertext.
// The ciphertext is stored in serialized form and all operations are delegated to C++.
type Ciphertext struct {
	serialized []byte
}

// Bytes returns the serialized ciphertext.
func (ct *Ciphertext) Bytes() []byte {
	return ct.serialized
}

// Q extracts the public key point Q from the ciphertext.
// See cb-mpc/src/cbmpc/protocol/pve.h for protocol details.
func (ct *Ciphertext) Q() (*cbmpc.CurvePoint, error) {
	if ct == nil || len(ct.serialized) == 0 {
		return nil, errors.New("nil or empty ciphertext")
	}

	cpoint, err := bindings.PVEGetQPoint(ct.serialized)
	if err != nil {
		return nil, cbmpc.RemapError(err)
	}

	return cbmpc.NewCurvePointFromBindings(cpoint), nil
}

// Label extracts the label from the ciphertext.
// See cb-mpc/src/cbmpc/protocol/pve.h for protocol details.
func (ct *Ciphertext) Label() ([]byte, error) {
	if ct == nil || len(ct.serialized) == 0 {
		return nil, errors.New("nil or empty ciphertext")
	}
	return bindings.PVEGetLabel(ct.serialized)
}

// EncryptParams contains parameters for PVE encryption.
type EncryptParams struct {
	// EK is the public encryption key bytes (serialized).
	EK []byte

	// Label is an application-specific label for the encryption.
	Label []byte

	// Curve specifies the elliptic curve to use.
	Curve cbmpc.Curve

	// X is the scalar value to encrypt.
	// NOTE: X.Bytes contains sensitive data. Consider zeroizing it after encryption
	// by calling cbmpc.ZeroizeBytes(X.Bytes) to clear it from memory.
	X *cbmpc.Scalar
}

// EncryptResult contains the result of PVE encryption.
type EncryptResult struct {
	// Ciphertext is the PVE ciphertext.
	Ciphertext *Ciphertext
}

// Encrypt encrypts a scalar x using publicly verifiable encryption.
// See cb-mpc/src/cbmpc/protocol/pve.h for protocol details.
func (pve *PVE) Encrypt(_ context.Context, params *EncryptParams) (*EncryptResult, error) {
	if pve == nil {
		return nil, errors.New("nil PVE instance")
	}
	if params == nil {
		return nil, errors.New("nil params")
	}
	if len(params.EK) == 0 {
		return nil, errors.New("empty encryption key")
	}
	if len(params.Label) == 0 {
		return nil, errors.New("empty label")
	}
	if params.X == nil {
		return nil, errors.New("nil scalar")
	}

	// Set the KEM for this operation (goroutine-local)
	cleanup := bindings.SetKEM(pve.kem)
	defer cleanup()

	// Use X.Bytes directly
	ctBytes, err := bindings.PVEEncrypt(params.EK, params.Label, params.Curve.NID(), params.X.Bytes)
	if err != nil {
		return nil, cbmpc.RemapError(err)
	}

	return &EncryptResult{
		Ciphertext: &Ciphertext{serialized: ctBytes},
	}, nil
}

// VerifyParams contains parameters for PVE verification.
type VerifyParams struct {
	// EK is the public encryption key bytes (serialized).
	EK []byte

	// Ciphertext is the PVE ciphertext to verify.
	Ciphertext *Ciphertext

	// Q is the expected public key point.
	Q *cbmpc.CurvePoint

	// Label is the expected label.
	Label []byte
}

// Verify verifies a PVE ciphertext against a public key Q and label.
// See cb-mpc/src/cbmpc/protocol/pve.h for protocol details.
func (pve *PVE) Verify(_ context.Context, params *VerifyParams) error {
	if pve == nil {
		return errors.New("nil PVE instance")
	}
	if params == nil {
		return errors.New("nil params")
	}
	if len(params.EK) == 0 {
		return errors.New("empty encryption key")
	}
	if params.Ciphertext == nil || len(params.Ciphertext.serialized) == 0 {
		return errors.New("nil or empty ciphertext")
	}
	if params.Q == nil {
		return errors.New("nil Q")
	}
	if len(params.Label) == 0 {
		return errors.New("empty label")
	}

	// Set the KEM for this operation (goroutine-local)
	cleanup := bindings.SetKEM(pve.kem)
	defer cleanup()

	err := bindings.PVEVerifyWithPoint(params.EK, params.Ciphertext.serialized, params.Q.CPtr(), params.Label)
	if err != nil {
		return cbmpc.RemapError(err)
	}

	return nil
}

// DecryptParams contains parameters for PVE decryption.
type DecryptParams struct {
	// DK is the private decryption key.
	// This can be any Go value - the bindings layer handles CGO safety automatically.
	// When passed through C code, it's automatically registered in a handle registry.
	DK any

	// EK is the public encryption key bytes (serialized).
	EK []byte

	// Ciphertext is the PVE ciphertext to decrypt.
	Ciphertext *Ciphertext

	// Label is the expected label.
	Label []byte

	// Curve specifies the elliptic curve.
	Curve cbmpc.Curve
}

// DecryptResult contains the result of PVE decryption.
type DecryptResult struct {
	// X is the decrypted scalar value.
	X *cbmpc.Scalar
}

// Decrypt decrypts a PVE ciphertext to recover the scalar x.
// See cb-mpc/src/cbmpc/protocol/pve.h for protocol details.
func (pve *PVE) Decrypt(_ context.Context, params *DecryptParams) (*DecryptResult, error) {
	if pve == nil {
		return nil, errors.New("nil PVE instance")
	}
	if params == nil {
		return nil, errors.New("nil params")
	}
	if params.DK == nil {
		return nil, errors.New("nil decryption key")
	}
	if len(params.EK) == 0 {
		return nil, errors.New("empty encryption key")
	}
	if params.Ciphertext == nil || len(params.Ciphertext.serialized) == 0 {
		return nil, errors.New("nil or empty ciphertext")
	}
	if len(params.Label) == 0 {
		return nil, errors.New("empty label")
	}

	// Set the KEM for this operation (goroutine-local)
	cleanup := bindings.SetKEM(pve.kem)
	defer cleanup()

	// Register the DK handle so it can be safely passed through C
	dkHandle := bindings.RegisterHandle(params.DK)
	defer bindings.FreeHandle(dkHandle)

	xBytes, err := bindings.PVEDecrypt(dkHandle, params.EK, params.Ciphertext.serialized, params.Label, params.Curve.NID())
	if err != nil {
		return nil, cbmpc.RemapError(err)
	}

	// Create Scalar from bytes
	x, err := cbmpc.NewScalarFromBytes(xBytes)
	if err != nil {
		cbmpc.ZeroizeBytes(xBytes)
		return nil, err
	}

	// Zeroize xBytes after use
	cbmpc.ZeroizeBytes(xBytes)
	runtime.KeepAlive(params)

	return &DecryptResult{X: x}, nil
}
