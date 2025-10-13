//go:build !cgo || windows

package zk

import (
	"github.com/coinbase/cb-mpc-go/pkg/cbmpc"
	"github.com/coinbase/cb-mpc-go/pkg/cbmpc/curve"
	"github.com/coinbase/cb-mpc-go/pkg/cbmpc/internal/backend"
)

// DLProof represents a UC discrete logarithm proof.
// This is a value type ([]byte) - no Close() needed, safe to copy and serialize.
type DLProof []byte

// DLProveParams contains parameters for UC_DL proof generation.
type DLProveParams struct {
	Point     *curve.Point
	Exponent  *curve.Scalar
	SessionID cbmpc.SessionID
	Aux       uint64
}

// Prove is a stub for non-CGO builds.
func Prove(params *DLProveParams) (DLProof, error) {
	return nil, backend.ErrNotBuilt
}

// DLVerifyParams contains parameters for UC_DL proof verification.
type DLVerifyParams struct {
	Proof     DLProof
	Point     *curve.Point
	SessionID cbmpc.SessionID
	Aux       uint64
}

// Verify is a stub for non-CGO builds.
func Verify(params *DLVerifyParams) error {
	return backend.ErrNotBuilt
}
