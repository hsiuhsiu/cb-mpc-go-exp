//go:build cgo && !windows

package zk

import (
	"errors"
	"runtime"

	"github.com/coinbase/cb-mpc-go/pkg/cbmpc"
	"github.com/coinbase/cb-mpc-go/pkg/cbmpc/curve"
	"github.com/coinbase/cb-mpc-go/pkg/cbmpc/internal/backend"
)

// ElGamalComProof represents a UC (universally composable) ElGamal commitment proof.
// This is a non-interactive zero-knowledge proof that proves knowledge of discrete logarithm x
// and randomness r such that UV = (r*G, x*Q + r*G), where G is the generator and Q is a public key.
//
// ElGamalComProof is a value type ([]byte) that can be safely copied, passed across goroutines,
// and serialized without resource management concerns. There is no Close() method or finalizer.
//
// Example:
//
//	proof, err := zk.ProveElGamalCom(&zk.ElGamalComProveParams{
//	    BasePoint:  Q,
//	    Commitment: uvCommitment,
//	    X:          xScalar,
//	    R:          rScalar,
//	    SessionID:  sessionID,
//	    Aux:        partyID,
//	})
//	if err != nil {
//	    return err
//	}
//	// No Close() needed - proof is just bytes
//	// Can serialize, pass to other goroutines, etc.
type ElGamalComProof []byte

// ElGamalComProveParams contains parameters for UC_ElGamalCom proof generation.
// This proves knowledge of x and r such that UV = (L, R) where L = r*G and R = x*Q + r*G.
type ElGamalComProveParams struct {
	BasePoint  *curve.Point        // The public base point Q
	Commitment *curve.ECElGamalCom // The ElGamal commitment UV = (L, R)
	X          *curve.Scalar       // The secret value (witness)
	R          *curve.Scalar       // The secret randomness (witness)
	SessionID  cbmpc.SessionID     // Session identifier for security
	Aux        uint64              // Auxiliary data (e.g., party identifier)
}

// ProveElGamalCom creates a UC_ElGamalCom proof for proving knowledge of x and r.
// Specifically, it proves knowledge of X and R such that Commitment = (R*G, X*BasePoint + R*G).
// Returns the proof as bytes - no Close() required, safe to copy and serialize.
// See cb-mpc/src/cbmpc/zk/zk_elgamal_com.h for protocol details.
func ProveElGamalCom(params *ElGamalComProveParams) (ElGamalComProof, error) {
	if params == nil {
		return nil, errors.New("nil params")
	}
	if params.BasePoint == nil {
		return nil, errors.New("nil base point")
	}
	if params.Commitment == nil {
		return nil, errors.New("nil commitment")
	}
	if params.X == nil {
		return nil, errors.New("nil X")
	}
	if params.R == nil {
		return nil, errors.New("nil R")
	}
	if params.SessionID.IsEmpty() {
		return nil, errors.New("empty session ID")
	}

	qPoint := params.BasePoint.CPtr()
	if qPoint == nil {
		return nil, errors.New("base point has been freed")
	}

	uvCommitment := params.Commitment.CPtr()
	if uvCommitment == nil {
		return nil, errors.New("commitment has been freed")
	}

	proofBytes, err := backend.UCElGamalComProve(
		qPoint,
		uvCommitment,
		params.X.Bytes,
		params.R.Bytes,
		params.SessionID.Bytes(),
		params.Aux,
	)
	if err != nil {
		return nil, cbmpc.RemapError(err)
	}

	runtime.KeepAlive(params.BasePoint)
	runtime.KeepAlive(params.Commitment)
	runtime.KeepAlive(params.X)
	runtime.KeepAlive(params.R)
	return ElGamalComProof(proofBytes), nil
}

// ElGamalComVerifyParams contains parameters for UC_ElGamalCom proof verification.
type ElGamalComVerifyParams struct {
	Proof      ElGamalComProof     // The proof to verify (just bytes, no pointer needed)
	BasePoint  *curve.Point        // The public base point Q
	Commitment *curve.ECElGamalCom // The ElGamal commitment UV = (L, R)
	SessionID  cbmpc.SessionID     // Session identifier (must match the one used in Prove)
	Aux        uint64              // Auxiliary data (must match the one used in Prove)
}

// VerifyElGamalCom verifies a UC_ElGamalCom proof.
// The proof bytes are not modified and remain valid.
// See cb-mpc/src/cbmpc/zk/zk_elgamal_com.h for protocol details.
func VerifyElGamalCom(params *ElGamalComVerifyParams) error {
	if params == nil {
		return errors.New("nil params")
	}
	if len(params.Proof) == 0 {
		return errors.New("empty proof")
	}
	if params.BasePoint == nil {
		return errors.New("nil base point")
	}
	if params.Commitment == nil {
		return errors.New("nil commitment")
	}
	if params.SessionID.IsEmpty() {
		return errors.New("empty session ID")
	}

	qPoint := params.BasePoint.CPtr()
	if qPoint == nil {
		return errors.New("base point has been freed")
	}

	uvCommitment := params.Commitment.CPtr()
	if uvCommitment == nil {
		return errors.New("commitment has been freed")
	}

	err := backend.UCElGamalComVerify(
		[]byte(params.Proof),
		qPoint,
		uvCommitment,
		params.SessionID.Bytes(),
		params.Aux,
	)
	if err != nil {
		return cbmpc.RemapError(err)
	}

	runtime.KeepAlive(params.BasePoint)
	runtime.KeepAlive(params.Commitment)
	return nil
}

// ElGamalComWithProof represents an ElGamal commitment together with its proof.
// This is a convenience type returned by MakeElGamalComWithProof.
type ElGamalComWithProof struct {
	Commitment *curve.ECElGamalCom // The ElGamal commitment UV = (r*G, x*Q + r*G)
	Proof      ElGamalComProof     // The ZK proof of knowledge of x and r
}

// MakeElGamalComWithProof is a convenience function that creates an ElGamal commitment
// and immediately generates a proof for it in one step. This reduces misuse by ensuring
// the commitment and proof are always consistent.
//
// This is equivalent to calling curve.MakeElGamalCom followed by ProveElGamalCom,
// but is more convenient and less error-prone when you have the witness available.
//
// The returned commitment must be freed with commitment.Free() when no longer needed.
func MakeElGamalComWithProof(basePoint *curve.Point, x, r *curve.Scalar, sessionID cbmpc.SessionID, aux uint64) (*ElGamalComWithProof, error) {
	if basePoint == nil {
		return nil, errors.New("nil base point")
	}
	if x == nil {
		return nil, errors.New("nil x")
	}
	if r == nil {
		return nil, errors.New("nil r")
	}
	if sessionID.IsEmpty() {
		return nil, errors.New("empty session ID")
	}

	// Create commitment
	commitment, err := curve.MakeElGamalCom(basePoint, x, r)
	if err != nil {
		return nil, err
	}

	// Generate proof
	proof, err := ProveElGamalCom(&ElGamalComProveParams{
		BasePoint:  basePoint,
		Commitment: commitment,
		X:          x,
		R:          r,
		SessionID:  sessionID,
		Aux:        aux,
	})
	if err != nil {
		commitment.Free()
		return nil, err
	}

	return &ElGamalComWithProof{
		Commitment: commitment,
		Proof:      proof,
	}, nil
}
