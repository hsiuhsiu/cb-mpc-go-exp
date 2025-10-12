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
