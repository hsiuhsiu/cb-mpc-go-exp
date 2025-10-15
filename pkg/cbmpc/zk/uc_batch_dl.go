//go:build cgo && !windows

package zk

import (
	"errors"
	"runtime"

	"github.com/coinbase/cb-mpc-go/pkg/cbmpc"
	"github.com/coinbase/cb-mpc-go/pkg/cbmpc/curve"
	"github.com/coinbase/cb-mpc-go/pkg/cbmpc/internal/backend"
)

// BatchDLProof represents a UC (universally composable) batch discrete logarithm proof.
// This is a non-interactive zero-knowledge proof that proves knowledge of multiple discrete logarithms w[i]
// such that Point[i] = w[i]*G (where G is the curve generator).
//
// BatchDLProof is a value type ([]byte) that can be safely copied, passed across goroutines,
// and serialized without resource management concerns. There is no Close() method or finalizer.
type BatchDLProof []byte

// BatchDLProveParams contains parameters for UC_Batch_DL proof generation.
// This proves knowledge of multiple discrete logarithms: Point[i] = Exponent[i] * G.
type BatchDLProveParams struct {
	Points    []*curve.Point  // The public curve points (Q[i] = w[i]*G)
	Exponents []*curve.Scalar // The secret discrete logarithms (witnesses w[i])
	SessionID cbmpc.SessionID // Session identifier for security
	Aux       uint64          // Auxiliary data (e.g., party identifier)
}

// ProveBatchDL creates a UC_Batch_DL proof for proving knowledge of multiple discrete logarithms.
// Specifically, it proves knowledge of Exponent[i] such that Point[i] = Exponent[i] * G.
// Returns the proof as bytes - no Close() required, safe to copy and serialize.
// See cb-mpc/src/cbmpc/zk/zk_ec.h for protocol details.
func ProveBatchDL(params *BatchDLProveParams) (BatchDLProof, error) {
	if params == nil {
		return nil, errors.New("nil params")
	}
	if len(params.Points) == 0 {
		return nil, errors.New("empty points")
	}
	if len(params.Exponents) == 0 {
		return nil, errors.New("empty exponents")
	}
	if len(params.Points) != len(params.Exponents) {
		return nil, errors.New("points and exponents count mismatch")
	}
	if params.SessionID.IsEmpty() {
		return nil, errors.New("empty session ID")
	}

	// Convert points to ECCPoint handles
	cPoints := make([]backend.ECCPoint, len(params.Points))
	for i, point := range params.Points {
		if point == nil {
			return nil, errors.New("nil point in points array")
		}
		cptr := point.CPtr()
		if cptr == nil {
			return nil, errors.New("point has been freed")
		}
		cPoints[i] = backend.ECCPoint(cptr)
		runtime.KeepAlive(point)
	}

	// Convert exponents to bytes
	exponentsBytes := make([][]byte, len(params.Exponents))
	for i, exponent := range params.Exponents {
		if exponent == nil {
			return nil, errors.New("nil exponent in exponents array")
		}
		exponentsBytes[i] = exponent.Bytes
		runtime.KeepAlive(exponent)
	}

	proofBytes, err := backend.UCBatchDLProve(cPoints, exponentsBytes, params.SessionID.Bytes(), params.Aux)
	if err != nil {
		return nil, cbmpc.RemapError(err)
	}

	// Keep all objects alive until after C completes
	for _, point := range params.Points {
		runtime.KeepAlive(point)
	}
	for _, exponent := range params.Exponents {
		runtime.KeepAlive(exponent)
	}

	return BatchDLProof(proofBytes), nil
}

// BatchDLVerifyParams contains parameters for UC_Batch_DL proof verification.
type BatchDLVerifyParams struct {
	Proof     BatchDLProof    // The proof to verify (just bytes, no pointer needed)
	Points    []*curve.Point  // The public curve points (Q[i] = w[i]*G)
	SessionID cbmpc.SessionID // Session identifier (must match the one used in Prove)
	Aux       uint64          // Auxiliary data (must match the one used in Prove)
}

// VerifyBatchDL verifies a UC_Batch_DL proof.
// The proof bytes are not modified and remain valid.
// See cb-mpc/src/cbmpc/zk/zk_ec.h for protocol details.
func VerifyBatchDL(params *BatchDLVerifyParams) error {
	if params == nil {
		return errors.New("nil params")
	}
	if len(params.Proof) == 0 {
		return errors.New("empty proof")
	}
	if len(params.Points) == 0 {
		return errors.New("empty points")
	}
	if params.SessionID.IsEmpty() {
		return errors.New("empty session ID")
	}

	// Convert points to ECCPoint handles
	cPoints := make([]backend.ECCPoint, len(params.Points))
	for i, point := range params.Points {
		if point == nil {
			return errors.New("nil point in points array")
		}
		cptr := point.CPtr()
		if cptr == nil {
			return errors.New("point has been freed")
		}
		cPoints[i] = backend.ECCPoint(cptr)
		runtime.KeepAlive(point)
	}

	err := backend.UCBatchDLVerify([]byte(params.Proof), cPoints, params.SessionID.Bytes(), params.Aux)
	if err != nil {
		return cbmpc.RemapError(err)
	}

	// Keep all objects alive until after C completes
	for _, point := range params.Points {
		runtime.KeepAlive(point)
	}

	return nil
}
