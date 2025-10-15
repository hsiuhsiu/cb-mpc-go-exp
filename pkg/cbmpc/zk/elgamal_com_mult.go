//go:build cgo && !windows

package zk

import (
	"errors"
	"runtime"

	"github.com/coinbase/cb-mpc-go/pkg/cbmpc"
	"github.com/coinbase/cb-mpc-go/pkg/cbmpc/curve"
	"github.com/coinbase/cb-mpc-go/pkg/cbmpc/internal/backend"
)

// ElGamalComMultProof represents a zero-knowledge proof for ElGamal commitment multiplication.
// This proves that C = b * A (scalar multiplication of commitment A by secret scalar b).
//
// ElGamalComMultProof is a value type ([]byte) that can be safely copied, passed across goroutines,
// and serialized without resource management concerns. There is no Close() method or finalizer.
type ElGamalComMultProof []byte

// ElGamalComMultProveParams contains parameters for ElGamal commitment multiplication proof generation.
type ElGamalComMultProveParams struct {
	Q         *curve.Point        // The base point Q
	A         *curve.ECElGamalCom // The ElGamal commitment A
	B         *curve.ECElGamalCom // The ElGamal commitment B
	C         *curve.ECElGamalCom // The ElGamal commitment C (should be b * A)
	RB        *curve.Scalar       // Randomness for commitment B (witness)
	RC        *curve.Scalar       // Randomness for commitment C (witness)
	ScalarB   *curve.Scalar       // The secret scalar multiplier (witness)
	SessionID cbmpc.SessionID     // Session identifier for security
	Aux       uint64              // Auxiliary data (e.g., party identifier)
}

// ProveElGamalComMult creates an ElGamal commitment multiplication proof.
// Returns the proof as bytes - no Close() required, safe to copy and serialize.
// See cb-mpc/src/cbmpc/zk/zk_elgamal_com.h for protocol details.
func ProveElGamalComMult(params *ElGamalComMultProveParams) (ElGamalComMultProof, error) {
	if params == nil {
		return nil, errors.New("nil params")
	}
	if params.Q == nil {
		return nil, errors.New("nil Q point")
	}
	if params.A == nil {
		return nil, errors.New("nil A commitment")
	}
	if params.B == nil {
		return nil, errors.New("nil B commitment")
	}
	if params.C == nil {
		return nil, errors.New("nil C commitment")
	}
	if params.RB == nil {
		return nil, errors.New("nil RB scalar")
	}
	if params.RC == nil {
		return nil, errors.New("nil RC scalar")
	}
	if params.ScalarB == nil {
		return nil, errors.New("nil ScalarB")
	}
	if params.SessionID.IsEmpty() {
		return nil, errors.New("empty session ID")
	}

	qPoint := params.Q.CPtr()
	if qPoint == nil {
		return nil, errors.New("Q point has been freed")
	}
	aCommitment := params.A.CPtr()
	if aCommitment == nil {
		return nil, errors.New("A commitment has been freed")
	}
	bCommitment := params.B.CPtr()
	if bCommitment == nil {
		return nil, errors.New("B commitment has been freed")
	}
	cCommitment := params.C.CPtr()
	if cCommitment == nil {
		return nil, errors.New("C commitment has been freed")
	}

	proofBytes, err := backend.ElGamalComMultProve(
		qPoint,
		aCommitment,
		bCommitment,
		cCommitment,
		params.RB.Bytes,
		params.RC.Bytes,
		params.ScalarB.Bytes,
		params.SessionID.Bytes(),
		params.Aux,
	)
	if err != nil {
		return nil, cbmpc.RemapError(err)
	}

	runtime.KeepAlive(params.Q)
	runtime.KeepAlive(params.A)
	runtime.KeepAlive(params.B)
	runtime.KeepAlive(params.C)
	runtime.KeepAlive(params.RB)
	runtime.KeepAlive(params.RC)
	runtime.KeepAlive(params.ScalarB)
	return ElGamalComMultProof(proofBytes), nil
}

// ElGamalComMultVerifyParams contains parameters for ElGamal commitment multiplication proof verification.
type ElGamalComMultVerifyParams struct {
	Proof     ElGamalComMultProof // The proof to verify (just bytes, no pointer needed)
	Q         *curve.Point        // The base point Q
	A         *curve.ECElGamalCom // The ElGamal commitment A
	B         *curve.ECElGamalCom // The ElGamal commitment B
	C         *curve.ECElGamalCom // The ElGamal commitment C (should be b * A)
	SessionID cbmpc.SessionID     // Session identifier (must match the one used in Prove)
	Aux       uint64              // Auxiliary data (must match the one used in Prove)
}

// VerifyElGamalComMult verifies an ElGamal commitment multiplication proof.
// The proof bytes are not modified and remain valid.
// See cb-mpc/src/cbmpc/zk/zk_elgamal_com.h for protocol details.
func VerifyElGamalComMult(params *ElGamalComMultVerifyParams) error {
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
		return errors.New("nil A commitment")
	}
	if params.B == nil {
		return errors.New("nil B commitment")
	}
	if params.C == nil {
		return errors.New("nil C commitment")
	}
	if params.SessionID.IsEmpty() {
		return errors.New("empty session ID")
	}

	qPoint := params.Q.CPtr()
	if qPoint == nil {
		return errors.New("Q point has been freed")
	}
	aCommitment := params.A.CPtr()
	if aCommitment == nil {
		return errors.New("A commitment has been freed")
	}
	bCommitment := params.B.CPtr()
	if bCommitment == nil {
		return errors.New("B commitment has been freed")
	}
	cCommitment := params.C.CPtr()
	if cCommitment == nil {
		return errors.New("C commitment has been freed")
	}

	err := backend.ElGamalComMultVerify(
		[]byte(params.Proof),
		qPoint,
		aCommitment,
		bCommitment,
		cCommitment,
		params.SessionID.Bytes(),
		params.Aux,
	)
	if err != nil {
		return cbmpc.RemapError(err)
	}

	runtime.KeepAlive(params.Q)
	runtime.KeepAlive(params.A)
	runtime.KeepAlive(params.B)
	runtime.KeepAlive(params.C)
	return nil
}
