//go:build cgo && !windows

package zk

import (
	"errors"
	"runtime"

	"github.com/coinbase/cb-mpc-go/pkg/cbmpc"
	"github.com/coinbase/cb-mpc-go/pkg/cbmpc/curve"
	"github.com/coinbase/cb-mpc-go/pkg/cbmpc/internal/backend"
)

// UCElGamalComMultPrivateScalarProof represents a universally composable zero-knowledge proof
// for ElGamal commitment multiplication with a private scalar.
// This proves that eB = c * eA with UC security.
//
// UCElGamalComMultPrivateScalarProof is a value type ([]byte) that can be safely copied,
// passed across goroutines, and serialized without resource management concerns.
// There is no Close() method or finalizer.
type UCElGamalComMultPrivateScalarProof []byte

// UCElGamalComMultPrivateScalarProveParams contains parameters for UC ElGamal commitment
// multiplication with private scalar proof generation.
type UCElGamalComMultPrivateScalarProveParams struct {
	E         *curve.Point        // The base point E
	EA        *curve.ECElGamalCom // The ElGamal commitment eA
	EB        *curve.ECElGamalCom // The ElGamal commitment eB (should be c * eA)
	R0        *curve.Scalar       // The randomness for eB (witness)
	C         *curve.Scalar       // The secret scalar multiplier (witness)
	SessionID cbmpc.SessionID     // Session identifier for security
	Aux       uint64              // Auxiliary data (e.g., party identifier)
}

// ProveUCElGamalComMultPrivateScalar creates a UC ElGamal commitment multiplication with private scalar proof.
// Returns the proof as bytes - no Close() required, safe to copy and serialize.
// See cb-mpc/src/cbmpc/zk/zk_elgamal_com.h for protocol details.
func ProveUCElGamalComMultPrivateScalar(params *UCElGamalComMultPrivateScalarProveParams) (UCElGamalComMultPrivateScalarProof, error) {
	if params == nil {
		return nil, errors.New("nil params")
	}
	if params.E == nil {
		return nil, errors.New("nil E point")
	}
	if params.EA == nil {
		return nil, errors.New("nil EA commitment")
	}
	if params.EB == nil {
		return nil, errors.New("nil EB commitment")
	}
	if params.R0 == nil {
		return nil, errors.New("nil R0 scalar")
	}
	if params.C == nil {
		return nil, errors.New("nil C scalar")
	}
	if params.SessionID.IsEmpty() {
		return nil, errors.New("empty session ID")
	}

	ePoint := params.E.CPtr()
	if ePoint == nil {
		return nil, errors.New("E point has been freed")
	}
	eaCommitment := params.EA.CPtr()
	if eaCommitment == nil {
		return nil, errors.New("EA commitment has been freed")
	}
	ebCommitment := params.EB.CPtr()
	if ebCommitment == nil {
		return nil, errors.New("EB commitment has been freed")
	}

	proofBytes, err := backend.UCElGamalComMultPrivateScalarProve(
		ePoint,
		eaCommitment,
		ebCommitment,
		params.R0.Bytes,
		params.C.Bytes,
		params.SessionID.Bytes(),
		params.Aux,
	)
	if err != nil {
		return nil, cbmpc.RemapError(err)
	}

	runtime.KeepAlive(params.E)
	runtime.KeepAlive(params.EA)
	runtime.KeepAlive(params.EB)
	runtime.KeepAlive(params.R0)
	runtime.KeepAlive(params.C)
	return UCElGamalComMultPrivateScalarProof(proofBytes), nil
}

// UCElGamalComMultPrivateScalarVerifyParams contains parameters for UC ElGamal commitment
// multiplication with private scalar proof verification.
type UCElGamalComMultPrivateScalarVerifyParams struct {
	Proof     UCElGamalComMultPrivateScalarProof // The proof to verify (just bytes, no pointer needed)
	E         *curve.Point                       // The base point E
	EA        *curve.ECElGamalCom                // The ElGamal commitment eA
	EB        *curve.ECElGamalCom                // The ElGamal commitment eB (should be c * eA)
	SessionID cbmpc.SessionID                    // Session identifier (must match the one used in Prove)
	Aux       uint64                             // Auxiliary data (must match the one used in Prove)
}

// VerifyUCElGamalComMultPrivateScalar verifies a UC ElGamal commitment multiplication with private scalar proof.
// The proof bytes are not modified and remain valid.
// See cb-mpc/src/cbmpc/zk/zk_elgamal_com.h for protocol details.
func VerifyUCElGamalComMultPrivateScalar(params *UCElGamalComMultPrivateScalarVerifyParams) error {
	if params == nil {
		return errors.New("nil params")
	}
	if len(params.Proof) == 0 {
		return errors.New("empty proof")
	}
	if params.E == nil {
		return errors.New("nil E point")
	}
	if params.EA == nil {
		return errors.New("nil EA commitment")
	}
	if params.EB == nil {
		return errors.New("nil EB commitment")
	}
	if params.SessionID.IsEmpty() {
		return errors.New("empty session ID")
	}

	ePoint := params.E.CPtr()
	if ePoint == nil {
		return errors.New("E point has been freed")
	}
	eaCommitment := params.EA.CPtr()
	if eaCommitment == nil {
		return errors.New("EA commitment has been freed")
	}
	ebCommitment := params.EB.CPtr()
	if ebCommitment == nil {
		return errors.New("EB commitment has been freed")
	}

	err := backend.UCElGamalComMultPrivateScalarVerify(
		[]byte(params.Proof),
		ePoint,
		eaCommitment,
		ebCommitment,
		params.SessionID.Bytes(),
		params.Aux,
	)
	if err != nil {
		return cbmpc.RemapError(err)
	}

	runtime.KeepAlive(params.E)
	runtime.KeepAlive(params.EA)
	runtime.KeepAlive(params.EB)
	return nil
}
