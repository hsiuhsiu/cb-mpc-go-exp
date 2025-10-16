//go:build !cgo || windows

package pve

import (
	"context"
	"errors"

	"github.com/coinbase/cb-mpc-go/pkg/cbmpc"
	"github.com/coinbase/cb-mpc-go/pkg/cbmpc/curve"
)

// PVE stub implementation for non-CGO builds.
type PVE struct{}

func New(cbmpc.KEM) (*PVE, error) {
	return nil, errors.New("PVE requires CGO")
}

type Ciphertext []byte

func (ct Ciphertext) Q() (*cbmpc.CurvePoint, error) {
	return nil, errors.New("PVE requires CGO")
}

func (ct Ciphertext) Label() ([]byte, error) {
	return nil, errors.New("PVE requires CGO")
}

type EncryptParams struct {
	EK    []byte
	Label []byte
	Curve cbmpc.Curve
	X     *curve.Scalar
}

type EncryptResult struct {
	Ciphertext Ciphertext
}

func (pve *PVE) Encrypt(_ context.Context, params *EncryptParams) (*EncryptResult, error) {
	return nil, errors.New("PVE requires CGO")
}

type VerifyParams struct {
	EK         []byte
	Ciphertext Ciphertext
	Q          *cbmpc.CurvePoint
	Label      []byte
}

func (pve *PVE) Verify(_ context.Context, params *VerifyParams) error {
	return errors.New("PVE requires CGO")
}

type DecryptParams struct {
	DK         any
	EK         []byte
	Ciphertext Ciphertext
	Label      []byte
	Curve      cbmpc.Curve
}

type DecryptResult struct {
	X *curve.Scalar
}

func (pve *PVE) Decrypt(_ context.Context, params *DecryptParams) (*DecryptResult, error) {
	return nil, errors.New("PVE requires CGO")
}

// Batch PVE operations

type BatchCiphertext []byte

type BatchEncryptParams struct {
	EK      []byte
	Label   []byte
	Curve   cbmpc.Curve
	Scalars []*curve.Scalar
}

type BatchEncryptResult struct {
	Ciphertext BatchCiphertext
}

func (pve *PVE) BatchEncrypt(_ context.Context, params *BatchEncryptParams) (*BatchEncryptResult, error) {
	return nil, errors.New("PVE requires CGO")
}

type BatchVerifyParams struct {
	EK         []byte
	Ciphertext BatchCiphertext
	Points     []*cbmpc.CurvePoint
	Label      []byte
}

func (pve *PVE) BatchVerify(_ context.Context, params *BatchVerifyParams) error {
	return errors.New("PVE requires CGO")
}

type BatchDecryptParams struct {
	DK         any
	EK         []byte
	Ciphertext BatchCiphertext
	Label      []byte
	Curve      cbmpc.Curve
}

type BatchDecryptResult struct {
	Scalars []*curve.Scalar
}

func (pve *PVE) BatchDecrypt(_ context.Context, params *BatchDecryptParams) (*BatchDecryptResult, error) {
	return nil, errors.New("PVE requires CGO")
}

// AC-based PVE operations

type ACCiphertext []byte

func (ct ACCiphertext) Bytes() []byte {
	return []byte(ct)
}

type ACEncryptParams struct {
	AC       []byte
	PathToEK map[string][]byte
	Label    []byte
	Curve    cbmpc.Curve
	Scalars  [][]byte
}

type ACEncryptResult struct {
	Ciphertext ACCiphertext
}

func (pve *PVE) ACEncrypt(_ context.Context, params *ACEncryptParams) (*ACEncryptResult, error) {
	return nil, errors.New("PVE requires CGO")
}
