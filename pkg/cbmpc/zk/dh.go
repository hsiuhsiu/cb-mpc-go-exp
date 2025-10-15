//go:build cgo && !windows

package zk

import (
	"errors"
	"runtime"

	"github.com/coinbase/cb-mpc-go/pkg/cbmpc"
	"github.com/coinbase/cb-mpc-go/pkg/cbmpc/curve"
	"github.com/coinbase/cb-mpc-go/pkg/cbmpc/internal/backend"
)

// DHProof represents a Diffie-Hellman zero-knowledge proof.
// This is a non-interactive zero-knowledge proof that proves knowledge of a discrete logarithm w
// such that A = w*G and B = w*Q (same discrete log for two different bases).
//
// DHProof is a value type ([]byte) that can be safely copied, passed across goroutines,
// and serialized without resource management concerns. There is no Close() method or finalizer.
type DHProof []byte

// DHProveParams contains parameters for DH proof generation.
// This proves knowledge of w such that A = w*G and B = w*Q.
type DHProveParams struct {
	Q         *curve.Point    // The base point Q
	A         *curve.Point    // The point A = w*G
	B         *curve.Point    // The point B = w*Q
	Exponent  *curve.Scalar   // The secret discrete logarithm (witness w)
	SessionID cbmpc.SessionID // Session identifier for security
	Aux       uint64          // Auxiliary data (e.g., party identifier)
}

// ProveDH creates a DH proof for proving B = w*Q where A = w*G.
// Returns the proof as bytes - no Close() required, safe to copy and serialize.
// See cb-mpc/src/cbmpc/zk/zk_ec.h for protocol details.
func ProveDH(params *DHProveParams) (DHProof, error) {
	if params == nil {
		return nil, errors.New("nil params")
	}
	if params.Q == nil {
		return nil, errors.New("nil Q point")
	}
	if params.A == nil {
		return nil, errors.New("nil A point")
	}
	if params.B == nil {
		return nil, errors.New("nil B point")
	}
	if params.Exponent == nil {
		return nil, errors.New("nil exponent")
	}
	if params.SessionID.IsEmpty() {
		return nil, errors.New("empty session ID")
	}

	qPoint := params.Q.CPtr()
	if qPoint == nil {
		return nil, errors.New("Q point has been freed")
	}
	aPoint := params.A.CPtr()
	if aPoint == nil {
		return nil, errors.New("A point has been freed")
	}
	bPoint := params.B.CPtr()
	if bPoint == nil {
		return nil, errors.New("B point has been freed")
	}

	proofBytes, err := backend.DHProve(qPoint, aPoint, bPoint, params.Exponent.Bytes, params.SessionID.Bytes(), params.Aux)
	if err != nil {
		return nil, cbmpc.RemapError(err)
	}

	runtime.KeepAlive(params.Q)
	runtime.KeepAlive(params.A)
	runtime.KeepAlive(params.B)
	runtime.KeepAlive(params.Exponent)
	return DHProof(proofBytes), nil
}

// DHVerifyParams contains parameters for DH proof verification.
type DHVerifyParams struct {
	Proof     DHProof         // The proof to verify (just bytes, no pointer needed)
	Q         *curve.Point    // The base point Q
	A         *curve.Point    // The point A (should be w*G)
	B         *curve.Point    // The point B (should be w*Q)
	SessionID cbmpc.SessionID // Session identifier (must match the one used in Prove)
	Aux       uint64          // Auxiliary data (must match the one used in Prove)
}

// VerifyDH verifies a DH proof.
// The proof bytes are not modified and remain valid.
// See cb-mpc/src/cbmpc/zk/zk_ec.h for protocol details.
func VerifyDH(params *DHVerifyParams) error {
	if params == nil {
		return errors.New("nil params")
	}
	if len(params.Proof) == 0 {
		return errors.New("empty proof")
	}
	if params.Q == nil {
		return errors.New("nil Q point")
	}
	if params.A == nil {
		return errors.New("nil A point")
	}
	if params.B == nil {
		return errors.New("nil B point")
	}
	if params.SessionID.IsEmpty() {
		return errors.New("empty session ID")
	}

	qPoint := params.Q.CPtr()
	if qPoint == nil {
		return errors.New("Q point has been freed")
	}
	aPoint := params.A.CPtr()
	if aPoint == nil {
		return errors.New("A point has been freed")
	}
	bPoint := params.B.CPtr()
	if bPoint == nil {
		return errors.New("B point has been freed")
	}

	err := backend.DHVerify([]byte(params.Proof), qPoint, aPoint, bPoint, params.SessionID.Bytes(), params.Aux)
	if err != nil {
		return cbmpc.RemapError(err)
	}

	runtime.KeepAlive(params.Q)
	runtime.KeepAlive(params.A)
	runtime.KeepAlive(params.B)
	return nil
}
