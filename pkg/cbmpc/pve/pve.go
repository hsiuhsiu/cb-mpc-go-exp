package pve

import (
	"context"
	"errors"
	"runtime"

	"github.com/coinbase/cb-mpc-go/pkg/cbmpc"
	"github.com/coinbase/cb-mpc-go/pkg/cbmpc/curve"
	"github.com/coinbase/cb-mpc-go/pkg/cbmpc/internal/backend"
)

// PVE represents a Publicly Verifiable Encryption instance with a specific KEM.
// Multiple PVE instances can coexist with different KEMs.
type PVE struct {
	kem cbmpc.KEM
}

// New creates a new PVE instance with the specified KEM.
// See cb-mpc/src/cbmpc/protocol/pve.h for protocol details.
func New(kem cbmpc.KEM) (*PVE, error) {
	if kem == nil {
		return nil, errors.New("nil KEM")
	}
	return &PVE{kem: kem}, nil
}

// Ciphertext represents a publicly verifiable encryption ciphertext.
type Ciphertext []byte

// Q extracts the public key point Q from the ciphertext.
// See cb-mpc/src/cbmpc/protocol/pve.h for protocol details.
func (ct Ciphertext) Q() (*cbmpc.CurvePoint, error) {
	if len(ct) == 0 {
		return nil, errors.New("empty ciphertext")
	}

	cpoint, err := backend.PVEGetQPoint(ct)
	if err != nil {
		return nil, cbmpc.RemapError(err)
	}

	return curve.NewPointFromBackend(cpoint), nil
}

// Label extracts the label from the ciphertext.
// See cb-mpc/src/cbmpc/protocol/pve.h for protocol details.
func (ct Ciphertext) Label() ([]byte, error) {
	if len(ct) == 0 {
		return nil, errors.New("empty ciphertext")
	}
	return backend.PVEGetLabel(ct)
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
	X *curve.Scalar
}

// EncryptResult contains the result of PVE encryption.
type EncryptResult struct {
	// Ciphertext is the PVE ciphertext.
	Ciphertext Ciphertext
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
	cleanup := backend.SetKEM(pve.kem)
	defer cleanup()

	nid, err := backend.CurveToNID(backend.Curve(params.Curve))
	if err != nil {
		return nil, err
	}

	// Use X.Bytes directly
	ctBytes, err := backend.PVEEncrypt(params.EK, params.Label, nid, params.X.Bytes)
	if err != nil {
		return nil, cbmpc.RemapError(err)
	}

	return &EncryptResult{
		Ciphertext: Ciphertext(ctBytes),
	}, nil
}

// VerifyParams contains parameters for PVE verification.
type VerifyParams struct {
	// EK is the public encryption key bytes (serialized).
	EK []byte

	// Ciphertext is the PVE ciphertext to verify.
	Ciphertext Ciphertext

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
	if len(params.Ciphertext) == 0 {
		return errors.New("empty ciphertext")
	}
	if params.Q == nil {
		return errors.New("nil Q")
	}
	if len(params.Label) == 0 {
		return errors.New("empty label")
	}

	// Set the KEM for this operation (goroutine-local)
	cleanup := backend.SetKEM(pve.kem)
	defer cleanup()

	err := backend.PVEVerifyWithPoint(params.EK, params.Ciphertext, params.Q.CPtr(), params.Label)
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
	Ciphertext Ciphertext

	// Label is the expected label.
	Label []byte

	// Curve specifies the elliptic curve.
	Curve cbmpc.Curve
}

// DecryptResult contains the result of PVE decryption.
type DecryptResult struct {
	// X is the decrypted scalar value.
	X *curve.Scalar
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
	if len(params.Ciphertext) == 0 {
		return nil, errors.New("empty ciphertext")
	}
	if len(params.Label) == 0 {
		return nil, errors.New("empty label")
	}

	// Set the KEM for this operation (goroutine-local)
	cleanup := backend.SetKEM(pve.kem)
	defer cleanup()

	nid, err := backend.CurveToNID(backend.Curve(params.Curve))
	if err != nil {
		return nil, err
	}

	// Register the DK handle so it can be safely passed through C
	dkHandle := backend.RegisterHandle(params.DK)
	defer backend.FreeHandle(dkHandle)

	xBytes, err := backend.PVEDecrypt(dkHandle, params.EK, params.Ciphertext, params.Label, nid)
	if err != nil {
		return nil, cbmpc.RemapError(err)
	}

	// Create Scalar from bytes
	x, err := curve.NewScalarFromBytes(xBytes)
	if err != nil {
		cbmpc.ZeroizeBytes(xBytes)
		return nil, err
	}

	// Zeroize xBytes after use
	cbmpc.ZeroizeBytes(xBytes)
	runtime.KeepAlive(params)

	return &DecryptResult{X: x}, nil
}
