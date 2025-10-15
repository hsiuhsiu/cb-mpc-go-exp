//go:build cgo && !windows

package zk

import (
	"errors"

	"github.com/coinbase/cb-mpc-go/pkg/cbmpc"
	"github.com/coinbase/cb-mpc-go/pkg/cbmpc/internal/backend"
	"github.com/coinbase/cb-mpc-go/pkg/cbmpc/paillier"
)

// ValidPaillierProof represents a zero-knowledge proof that a Paillier key is well-formed.
// This proof demonstrates that a Paillier modulus N was correctly generated without small factors,
// ensuring the security of the Paillier cryptosystem.
//
// ValidPaillierProof is a value type ([]byte) that can be safely copied, passed across goroutines,
// and serialized without resource management concerns. There is no Close() method or finalizer.
//
// Example:
//
//	proof, err := zk.ProveValidPaillier(&zk.ValidPaillierProveParams{
//	    Paillier:  paillierKey,
//	    SessionID: sessionID,
//	    Aux:       partyID,
//	})
//	if err != nil {
//	    return err
//	}
//	// No Close() needed - proof is just bytes
//	// Can serialize, pass to other goroutines, etc.
type ValidPaillierProof []byte

// ValidPaillierProveParams contains parameters for Valid_Paillier proof generation.
// This proves that a Paillier key was correctly generated without small factors.
type ValidPaillierProveParams struct {
	Paillier  *paillier.Paillier // The Paillier key to prove validity for (must have private key)
	SessionID cbmpc.SessionID    // Session identifier for security
	Aux       uint64             // Auxiliary data (e.g., party identifier)
}

// ProveValidPaillier creates a Valid_Paillier proof for proving that a Paillier key is well-formed.
// The Paillier instance must have a private key (generated via paillier.Generate() or paillier.FromPrivateKey()).
// Returns the proof as bytes - no Close() required, safe to copy and serialize.
// See cb-mpc/src/cbmpc/zk/zk_paillier.h for protocol details.
func ProveValidPaillier(params *ValidPaillierProveParams) (ValidPaillierProof, error) {
	if params == nil {
		return nil, errors.New("nil params")
	}
	if params.Paillier == nil {
		return nil, errors.New("nil paillier")
	}
	if params.SessionID.IsEmpty() {
		return nil, errors.New("empty session ID")
	}

	handle := params.Paillier.Handle()
	if handle == nil {
		return nil, errors.New("paillier has been closed")
	}

	if !params.Paillier.HasPrivateKey() {
		return nil, errors.New("paillier must have private key to prove validity")
	}

	proofBytes, err := backend.ValidPaillierProve(handle, params.SessionID.Bytes(), params.Aux)
	if err != nil {
		return nil, cbmpc.RemapError(err)
	}

	return ValidPaillierProof(proofBytes), nil
}

// ValidPaillierVerifyParams contains parameters for Valid_Paillier proof verification.
type ValidPaillierVerifyParams struct {
	Proof     ValidPaillierProof // The proof to verify (just bytes, no pointer needed)
	Paillier  *paillier.Paillier // The Paillier key to verify (can be public key only)
	SessionID cbmpc.SessionID    // Session identifier (must match the one used in Prove)
	Aux       uint64             // Auxiliary data (must match the one used in Prove)
}

// VerifyValidPaillier verifies a Valid_Paillier proof.
// The Paillier instance can be a public key only (no private key required for verification).
// The proof bytes are not modified and remain valid.
// See cb-mpc/src/cbmpc/zk/zk_paillier.h for protocol details.
func VerifyValidPaillier(params *ValidPaillierVerifyParams) error {
	if params == nil {
		return errors.New("nil params")
	}
	if len(params.Proof) == 0 {
		return errors.New("empty proof")
	}
	if params.Paillier == nil {
		return errors.New("nil paillier")
	}
	if params.SessionID.IsEmpty() {
		return errors.New("empty session ID")
	}

	handle := params.Paillier.Handle()
	if handle == nil {
		return errors.New("paillier has been closed")
	}

	err := backend.ValidPaillierVerify([]byte(params.Proof), handle, params.SessionID.Bytes(), params.Aux)
	if err != nil {
		return cbmpc.RemapError(err)
	}

	return nil
}
