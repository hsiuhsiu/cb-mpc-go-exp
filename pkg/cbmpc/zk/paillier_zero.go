//go:build cgo && !windows

package zk

import (
	"errors"

	"github.com/coinbase/cb-mpc-go/pkg/cbmpc"
	"github.com/coinbase/cb-mpc-go/pkg/cbmpc/internal/backend"
	"github.com/coinbase/cb-mpc-go/pkg/cbmpc/paillier"
)

// PaillierZeroProof represents a zero-knowledge proof that a Paillier ciphertext encrypts zero.
// This proof demonstrates that a ciphertext c was created with plaintext = 0, without revealing
// the randomness used in the encryption.
//
// PaillierZeroProof is a value type ([]byte) that can be safely copied, passed across goroutines,
// and serialized without resource management concerns. There is no Close() method or finalizer.
type PaillierZeroProof []byte

// PaillierZeroProveParams contains parameters for Paillier_Zero proof generation.
// This proves that a Paillier ciphertext encrypts zero.
type PaillierZeroProveParams struct {
	Paillier  *paillier.Paillier // The Paillier key used for encryption (must have private key)
	C         []byte             // The ciphertext to prove encrypts zero
	R         []byte             // The randomness used to create the ciphertext
	SessionID cbmpc.SessionID    // Session identifier for security
	Aux       uint64             // Auxiliary data (e.g., party identifier)
}

// ProvePaillierZero creates a Paillier_Zero proof for proving that a ciphertext encrypts zero.
// The Paillier instance must have a private key.
// Returns the proof as bytes - no Close() required, safe to copy and serialize.
// See cb-mpc/src/cbmpc/zk/zk_paillier.h for protocol details.
func ProvePaillierZero(params *PaillierZeroProveParams) (PaillierZeroProof, error) {
	if params == nil {
		return nil, errors.New("nil params")
	}
	if params.Paillier == nil {
		return nil, errors.New("nil paillier")
	}
	if len(params.C) == 0 {
		return nil, errors.New("empty ciphertext")
	}
	if len(params.R) == 0 {
		return nil, errors.New("empty randomness")
	}
	if params.SessionID.IsEmpty() {
		return nil, errors.New("empty session ID")
	}

	handle := params.Paillier.Handle()
	if handle == nil {
		return nil, errors.New("paillier has been closed")
	}

	if !params.Paillier.HasPrivateKey() {
		return nil, errors.New("paillier must have private key to prove")
	}

	proofBytes, err := backend.PaillierZeroProve(handle, params.C, params.R, params.SessionID.Bytes(), params.Aux)
	if err != nil {
		return nil, cbmpc.RemapError(err)
	}

	return PaillierZeroProof(proofBytes), nil
}

// PaillierZeroVerifyParams contains parameters for Paillier_Zero proof verification.
type PaillierZeroVerifyParams struct {
	Proof     PaillierZeroProof  // The proof to verify
	Paillier  *paillier.Paillier // The Paillier key (can be public key only)
	C         []byte             // The ciphertext claimed to encrypt zero
	SessionID cbmpc.SessionID    // Session identifier (must match the one used in Prove)
	Aux       uint64             // Auxiliary data (must match the one used in Prove)
}

// VerifyPaillierZero verifies a Paillier_Zero proof.
// The Paillier instance can be a public key only (no private key required for verification).
// See cb-mpc/src/cbmpc/zk/zk_paillier.h for protocol details.
func VerifyPaillierZero(params *PaillierZeroVerifyParams) error {
	if params == nil {
		return errors.New("nil params")
	}
	if len(params.Proof) == 0 {
		return errors.New("empty proof")
	}
	if params.Paillier == nil {
		return errors.New("nil paillier")
	}
	if len(params.C) == 0 {
		return errors.New("empty ciphertext")
	}
	if params.SessionID.IsEmpty() {
		return errors.New("empty session ID")
	}

	handle := params.Paillier.Handle()
	if handle == nil {
		return errors.New("paillier has been closed")
	}

	err := backend.PaillierZeroVerify([]byte(params.Proof), handle, params.C, params.SessionID.Bytes(), params.Aux)
	if err != nil {
		return cbmpc.RemapError(err)
	}

	return nil
}
