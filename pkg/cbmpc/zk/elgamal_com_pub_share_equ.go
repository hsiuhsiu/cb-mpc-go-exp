//go:build cgo && !windows

package zk

import (
	"errors"
	"runtime"

	"github.com/coinbase/cb-mpc-go/pkg/cbmpc"
	"github.com/coinbase/cb-mpc-go/pkg/cbmpc/curve"
	"github.com/coinbase/cb-mpc-go/pkg/cbmpc/internal/backend"
)

// ElGamalComPubShareEquProof represents a zero-knowledge proof for ElGamal commitment public share equality.
// This proves that A and the public share of B are equal: A = r*G where B.L = r*G.
//
// ElGamalComPubShareEquProof is a value type ([]byte) that can be safely copied, passed across goroutines,
// and serialized without resource management concerns. There is no Close() method or finalizer.
type ElGamalComPubShareEquProof []byte

// ElGamalComPubShareEquProveParams contains parameters for ElGamal commitment public share equality proof generation.
type ElGamalComPubShareEquProveParams struct {
	Q         *curve.Point        // The base point Q
	A         *curve.Point        // The public point A = r*G
	B         *curve.ECElGamalCom // The ElGamal commitment B where B.L should equal A
	R         *curve.Scalar       // The secret randomness (witness)
	SessionID cbmpc.SessionID     // Session identifier for security
	Aux       uint64              // Auxiliary data (e.g., party identifier)
}

// ProveElGamalComPubShareEqu creates an ElGamal commitment public share equality proof.
// Returns the proof as bytes - no Close() required, safe to copy and serialize.
// See cb-mpc/src/cbmpc/zk/zk_elgamal_com.h for protocol details.
func ProveElGamalComPubShareEqu(params *ElGamalComPubShareEquProveParams) (ElGamalComPubShareEquProof, error) {
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
		return nil, errors.New("nil B commitment")
	}
	if params.R == nil {
		return nil, errors.New("nil R scalar")
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
	bCommitment := params.B.CPtr()
	if bCommitment == nil {
		return nil, errors.New("B commitment has been freed")
	}

	proofBytes, err := backend.ElGamalComPubShareEquProve(qPoint, aPoint, bCommitment, params.R.Bytes, params.SessionID.Bytes(), params.Aux)
	if err != nil {
		return nil, cbmpc.RemapError(err)
	}

	runtime.KeepAlive(params.Q)
	runtime.KeepAlive(params.A)
	runtime.KeepAlive(params.B)
	runtime.KeepAlive(params.R)
	return ElGamalComPubShareEquProof(proofBytes), nil
}

// ElGamalComPubShareEquVerifyParams contains parameters for ElGamal commitment public share equality proof verification.
type ElGamalComPubShareEquVerifyParams struct {
	Proof     ElGamalComPubShareEquProof // The proof to verify (just bytes, no pointer needed)
	Q         *curve.Point               // The base point Q
	A         *curve.Point               // The public point A (should be r*G)
	B         *curve.ECElGamalCom        // The ElGamal commitment B (B.L should equal A)
	SessionID cbmpc.SessionID            // Session identifier (must match the one used in Prove)
	Aux       uint64                     // Auxiliary data (must match the one used in Prove)
}

// VerifyElGamalComPubShareEqu verifies an ElGamal commitment public share equality proof.
// The proof bytes are not modified and remain valid.
// See cb-mpc/src/cbmpc/zk/zk_elgamal_com.h for protocol details.
func VerifyElGamalComPubShareEqu(params *ElGamalComPubShareEquVerifyParams) error {
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
		return errors.New("nil B commitment")
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
	bCommitment := params.B.CPtr()
	if bCommitment == nil {
		return errors.New("B commitment has been freed")
	}

	err := backend.ElGamalComPubShareEquVerify([]byte(params.Proof), qPoint, aPoint, bCommitment, params.SessionID.Bytes(), params.Aux)
	if err != nil {
		return cbmpc.RemapError(err)
	}

	runtime.KeepAlive(params.Q)
	runtime.KeepAlive(params.A)
	runtime.KeepAlive(params.B)
	return nil
}
