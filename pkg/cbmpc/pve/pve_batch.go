//go:build cgo && !windows

package pve

import (
	"context"
	"errors"
	"runtime"

	"github.com/coinbase/cb-mpc-go/pkg/cbmpc"
	"github.com/coinbase/cb-mpc-go/pkg/cbmpc/curve"
	"github.com/coinbase/cb-mpc-go/pkg/cbmpc/internal/backend"
)

// BatchCiphertext represents a batch PVE ciphertext containing multiple encrypted scalars.
// Unlike single PVE Ciphertext, batch ciphertexts do not expose Q() or Label() methods
// since the internal structure is different.
type BatchCiphertext []byte

// BatchEncryptParams contains parameters for batch PVE encryption.
type BatchEncryptParams struct {
	// EK is the public encryption key bytes (serialized).
	EK []byte

	// Label is an application-specific label for the encryption.
	Label []byte

	// Curve specifies the elliptic curve to use.
	Curve cbmpc.Curve

	// Scalars is the list of scalar values to encrypt in batch.
	// NOTE: Each Scalar's Bytes field contains sensitive data.
	// If you no longer need the inputs, call s.Free() to zeroize.
	Scalars []*curve.Scalar
}

// BatchEncryptResult contains the result of batch PVE encryption.
type BatchEncryptResult struct {
	// Ciphertext is the batch PVE ciphertext containing all encrypted scalars.
	Ciphertext BatchCiphertext
}

// BatchEncrypt encrypts multiple scalars using publicly verifiable encryption in a single batch operation.
// See cb-mpc/src/cbmpc/protocol/pve_batch.h for protocol details.
func (pve *PVE) BatchEncrypt(_ context.Context, params *BatchEncryptParams) (*BatchEncryptResult, error) {
	if pve == nil {
		return nil, errors.New("nil PVE instance")
	}
	if params == nil {
		return nil, errors.New("nil params")
	}
	if len(params.Scalars) == 0 {
		return nil, errors.New("empty scalars list")
	}

	nid, err := backend.CurveToNID(backend.Curve(params.Curve))
	if err != nil {
		return nil, err
	}

	// Convert scalars to [][]byte
	xScalarsBytes := make([][]byte, len(params.Scalars))
	for i, s := range params.Scalars {
		if s == nil {
			return nil, errors.New("nil scalar in scalars list")
		}
		xScalarsBytes[i] = s.Bytes
	}

	ctBytes, err := backend.PVEBatchEncrypt(pve.kem, params.EK, params.Label, nid, xScalarsBytes)
	if err != nil {
		return nil, cbmpc.RemapError(err)
	}

	return &BatchEncryptResult{
		Ciphertext: BatchCiphertext(ctBytes),
	}, nil
}

// BatchVerifyParams contains parameters for batch PVE verification.
type BatchVerifyParams struct {
	// EK is the public encryption key bytes (serialized).
	EK []byte

	// Ciphertext is the batch PVE ciphertext to verify.
	Ciphertext BatchCiphertext

	// Points is the list of expected public key points corresponding to each encrypted scalar.
	Points []*cbmpc.CurvePoint

	// Label is the expected label.
	Label []byte
}

// BatchVerify verifies a batch PVE ciphertext against a list of public key points and label.
// See cb-mpc/src/cbmpc/protocol/pve_batch.h for protocol details.
func (pve *PVE) BatchVerify(_ context.Context, params *BatchVerifyParams) error {
	if pve == nil {
		return errors.New("nil PVE instance")
	}
	if params == nil {
		return errors.New("nil params")
	}
	if len(params.Points) == 0 {
		return errors.New("empty points list")
	}

	// Convert []*cbmpc.CurvePoint to []backend.ECCPoint
	qPoints := make([]backend.ECCPoint, len(params.Points))
	for i, p := range params.Points {
		if p == nil {
			return errors.New("nil point in points list")
		}
		qPoints[i] = p.CPtr()
	}

	err := backend.PVEBatchVerify(pve.kem, params.EK, params.Ciphertext, qPoints, params.Label)
	if err != nil {
		return cbmpc.RemapError(err)
	}

	return nil
}

// BatchDecryptParams contains parameters for batch PVE decryption.
type BatchDecryptParams struct {
	// DK is the private decryption key.
	// This can be any Go value - the bindings layer handles CGO safety automatically.
	// When passed through C code, it's automatically registered in a handle registry.
	DK any

	// EK is the public encryption key bytes (serialized).
	EK []byte

	// Ciphertext is the batch PVE ciphertext to decrypt.
	Ciphertext BatchCiphertext

	// Label is the expected label.
	Label []byte

	// Curve specifies the elliptic curve.
	Curve cbmpc.Curve
}

// BatchDecryptResult contains the result of batch PVE decryption.
type BatchDecryptResult struct {
	// Scalars is the list of decrypted scalar values.
	Scalars []*curve.Scalar
}

// BatchDecrypt decrypts a batch PVE ciphertext to recover multiple scalar values.
// See cb-mpc/src/cbmpc/protocol/pve_batch.h for protocol details.
func (pve *PVE) BatchDecrypt(_ context.Context, params *BatchDecryptParams) (*BatchDecryptResult, error) {
	if pve == nil {
		return nil, errors.New("nil PVE instance")
	}
	if params == nil {
		return nil, errors.New("nil params")
	}
	if params.DK == nil {
		return nil, errors.New("nil decryption key")
	}

	nid, err := backend.CurveToNID(backend.Curve(params.Curve))
	if err != nil {
		return nil, err
	}

	// Register the DK handle so it can be safely passed through C
	dkHandle := backend.RegisterHandle(params.DK)
	defer backend.FreeHandle(dkHandle)

	xScalarsBytes, err := backend.PVEBatchDecrypt(pve.kem, dkHandle, params.EK, params.Ciphertext, params.Label, nid)
	if err != nil {
		return nil, cbmpc.RemapError(err)
	}

	// Convert [][]byte to []*curve.Scalar
	scalars := make([]*curve.Scalar, len(xScalarsBytes))
	for i, xBytes := range xScalarsBytes {
		s, err := curve.NewScalarFromBytes(xBytes)
		if err != nil {
			// Zeroize already processed scalars and the failed one
			for j := 0; j < i; j++ {
				cbmpc.ZeroizeBytes(scalars[j].Bytes)
			}
			cbmpc.ZeroizeBytes(xBytes)
			return nil, err
		}
		scalars[i] = s
		// Zeroize the temporary byte slice
		cbmpc.ZeroizeBytes(xBytes)
	}

	runtime.KeepAlive(params)

	return &BatchDecryptResult{Scalars: scalars}, nil
}

// Security note: Ciphertext slices are passed to C using pointers into Go memory for the
// duration of the call. Callers must treat Ciphertext as immutable while an API call is in
// progress to avoid time-of-check/time-of-use races. Do not mutate or reuse backing arrays
// concurrently with BatchEncrypt/BatchVerify/BatchDecrypt operations.
