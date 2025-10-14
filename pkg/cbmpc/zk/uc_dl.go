//go:build cgo && !windows

package zk

import (
	"errors"
	"runtime"

	"github.com/coinbase/cb-mpc-go/pkg/cbmpc"
	"github.com/coinbase/cb-mpc-go/pkg/cbmpc/curve"
	"github.com/coinbase/cb-mpc-go/pkg/cbmpc/internal/backend"
)

// DLProof represents a UC (universally composable) discrete logarithm proof.
// This is a non-interactive zero-knowledge proof that proves knowledge of a discrete logarithm w
// such that Point = w*G (where G is the curve generator).
//
// DLProof is a value type ([]byte) that can be safely copied, passed across goroutines,
// and serialized without resource management concerns. There is no Close() method or finalizer.
//
// Example:
//
//	proof, err := zk.Prove(&zk.DLProveParams{
//	    Point:      curvePoint,
//	    Exponent:   scalar,
//	    SessionID:  sessionID,
//	    Aux:        partyID,
//	})
//	if err != nil {
//	    return err
//	}
//	// No Close() needed - proof is just bytes
//	// Can serialize, pass to other goroutines, etc.
type DLProof []byte

// DLProveParams contains parameters for UC_DL proof generation.
// This proves knowledge of the discrete logarithm: Point = Exponent * G.
type DLProveParams struct {
	Point     *curve.Point    // The public curve point (Q = w*G)
	Exponent  *curve.Scalar   // The secret discrete logarithm (witness w)
	SessionID cbmpc.SessionID // Session identifier for security
	Aux       uint64          // Auxiliary data (e.g., party identifier)
}

// Prove creates a UC_DL proof for proving knowledge of the discrete logarithm.
// Specifically, it proves knowledge of Exponent such that Point = Exponent * G.
// Returns the proof as bytes - no Close() required, safe to copy and serialize.
// See cb-mpc/src/cbmpc/zk/zk_ec.h for protocol details.
func Prove(params *DLProveParams) (DLProof, error) {
	if params == nil {
		return nil, errors.New("nil params")
	}
	if params.Point == nil {
		return nil, errors.New("nil point")
	}
	if params.Exponent == nil {
		return nil, errors.New("nil exponent")
	}
	if params.SessionID.IsEmpty() {
		return nil, errors.New("empty session ID")
	}

	qPoint := params.Point.CPtr()
	if qPoint == nil {
		return nil, errors.New("point has been freed")
	}

	proofBytes, err := backend.UCDLProve(qPoint, params.Exponent.Bytes, params.SessionID.Bytes(), params.Aux)
	if err != nil {
		return nil, cbmpc.RemapError(err)
	}

	runtime.KeepAlive(params.Point)
	runtime.KeepAlive(params.Exponent)
	return DLProof(proofBytes), nil
}

// DLVerifyParams contains parameters for UC_DL proof verification.
type DLVerifyParams struct {
	Proof     DLProof         // The proof to verify (just bytes, no pointer needed)
	Point     *curve.Point    // The public curve point (Q = w*G)
	SessionID cbmpc.SessionID // Session identifier (must match the one used in Prove)
	Aux       uint64          // Auxiliary data (must match the one used in Prove)
}

// Verify verifies a UC_DL proof.
// The proof bytes are not modified and remain valid.
// See cb-mpc/src/cbmpc/zk/zk_ec.h for protocol details.
func Verify(params *DLVerifyParams) error {
	if params == nil {
		return errors.New("nil params")
	}
	if len(params.Proof) == 0 {
		return errors.New("empty proof")
	}
	if params.Point == nil {
		return errors.New("nil point")
	}
	if params.SessionID.IsEmpty() {
		return errors.New("empty session ID")
	}

	qPoint := params.Point.CPtr()
	if qPoint == nil {
		return errors.New("point has been freed")
	}

	err := backend.UCDLVerify([]byte(params.Proof), qPoint, params.SessionID.Bytes(), params.Aux)
	if err != nil {
		return cbmpc.RemapError(err)
	}

	runtime.KeepAlive(params.Point)
	return nil
}
