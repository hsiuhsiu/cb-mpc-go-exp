//go:build cgo && !windows

package zk

import (
	"errors"

	"github.com/coinbase/cb-mpc-go/pkg/cbmpc"
	"github.com/coinbase/cb-mpc-go/pkg/cbmpc/internal/backend"
	"github.com/coinbase/cb-mpc-go/pkg/cbmpc/paillier"
)

// TwoPaillierEqualProof represents a zero-knowledge proof that two Paillier ciphertexts
// (under different keys) encrypt the same plaintext.
// This proof demonstrates that c0 (encrypted under P0) and c1 (encrypted under P1)
// both encrypt the same value x, without revealing x or the randomness.
//
// TwoPaillierEqualProof is a value type ([]byte) that can be safely copied, passed across goroutines,
// and serialized without resource management concerns. There is no Close() method or finalizer.
type TwoPaillierEqualProof []byte

// TwoPaillierEqualProveParams contains parameters for Two_Paillier_Equal proof generation.
// This proves that two ciphertexts under different Paillier keys encrypt the same plaintext.
type TwoPaillierEqualProveParams struct {
	Q         []byte             // Modulus q (for range proofs)
	P0        *paillier.Paillier // First Paillier key (must have private key)
	C0        []byte             // First ciphertext (encrypted under P0)
	P1        *paillier.Paillier // Second Paillier key (must have private key)
	C1        []byte             // Second ciphertext (encrypted under P1)
	X         []byte             // The plaintext encrypted in both c0 and c1
	R0        []byte             // Randomness used to create c0
	R1        []byte             // Randomness used to create c1
	SessionID cbmpc.SessionID    // Session identifier for security
	Aux       uint64             // Auxiliary data (e.g., party identifier)
}

// ProveTwoPaillierEqual creates a Two_Paillier_Equal proof for proving that two ciphertexts
// encrypt the same plaintext under different Paillier keys.
// Both Paillier instances must have private keys.
// Returns the proof as bytes - no Close() required, safe to copy and serialize.
// See cb-mpc/src/cbmpc/zk/zk_paillier.h for protocol details.
func ProveTwoPaillierEqual(params *TwoPaillierEqualProveParams) (TwoPaillierEqualProof, error) {
	if params == nil {
		return nil, errors.New("nil params")
	}
	if len(params.Q) == 0 {
		return nil, errors.New("empty modulus q")
	}
	if params.P0 == nil {
		return nil, errors.New("nil paillier P0")
	}
	if len(params.C0) == 0 {
		return nil, errors.New("empty ciphertext c0")
	}
	if params.P1 == nil {
		return nil, errors.New("nil paillier P1")
	}
	if len(params.C1) == 0 {
		return nil, errors.New("empty ciphertext c1")
	}
	if len(params.X) == 0 {
		return nil, errors.New("empty plaintext x")
	}
	if len(params.R0) == 0 {
		return nil, errors.New("empty randomness r0")
	}
	if len(params.R1) == 0 {
		return nil, errors.New("empty randomness r1")
	}
	if params.SessionID.IsEmpty() {
		return nil, errors.New("empty session ID")
	}

	handle0 := params.P0.Handle()
	if handle0 == nil {
		return nil, errors.New("paillier P0 has been closed")
	}

	handle1 := params.P1.Handle()
	if handle1 == nil {
		return nil, errors.New("paillier P1 has been closed")
	}

	if !params.P0.HasPrivateKey() {
		return nil, errors.New("paillier P0 must have private key to prove")
	}

	if !params.P1.HasPrivateKey() {
		return nil, errors.New("paillier P1 must have private key to prove")
	}

	proofBytes, err := backend.TwoPaillierEqualProve(
		params.Q,
		handle0,
		params.C0,
		handle1,
		params.C1,
		params.X,
		params.R0,
		params.R1,
		params.SessionID.Bytes(),
		params.Aux,
	)
	if err != nil {
		return nil, cbmpc.RemapError(err)
	}

	return TwoPaillierEqualProof(proofBytes), nil
}

// TwoPaillierEqualVerifyParams contains parameters for Two_Paillier_Equal proof verification.
type TwoPaillierEqualVerifyParams struct {
	Proof     TwoPaillierEqualProof // The proof to verify
	Q         []byte                // Modulus q (must match the one used in Prove)
	P0        *paillier.Paillier    // First Paillier key (can be public key only)
	C0        []byte                // First ciphertext
	P1        *paillier.Paillier    // Second Paillier key (can be public key only)
	C1        []byte                // Second ciphertext
	SessionID cbmpc.SessionID       // Session identifier (must match the one used in Prove)
	Aux       uint64                // Auxiliary data (must match the one used in Prove)
}

// VerifyTwoPaillierEqual verifies a Two_Paillier_Equal proof.
// Both Paillier instances can be public keys only (no private keys required for verification).
// See cb-mpc/src/cbmpc/zk/zk_paillier.h for protocol details.
func VerifyTwoPaillierEqual(params *TwoPaillierEqualVerifyParams) error {
	if params == nil {
		return errors.New("nil params")
	}
	if len(params.Proof) == 0 {
		return errors.New("empty proof")
	}
	if len(params.Q) == 0 {
		return errors.New("empty modulus q")
	}
	if params.P0 == nil {
		return errors.New("nil paillier P0")
	}
	if len(params.C0) == 0 {
		return errors.New("empty ciphertext c0")
	}
	if params.P1 == nil {
		return errors.New("nil paillier P1")
	}
	if len(params.C1) == 0 {
		return errors.New("empty ciphertext c1")
	}
	if params.SessionID.IsEmpty() {
		return errors.New("empty session ID")
	}

	handle0 := params.P0.Handle()
	if handle0 == nil {
		return errors.New("paillier P0 has been closed")
	}

	handle1 := params.P1.Handle()
	if handle1 == nil {
		return errors.New("paillier P1 has been closed")
	}

	err := backend.TwoPaillierEqualVerify(
		[]byte(params.Proof),
		params.Q,
		handle0,
		params.C0,
		handle1,
		params.C1,
		params.SessionID.Bytes(),
		params.Aux,
	)
	if err != nil {
		return cbmpc.RemapError(err)
	}

	return nil
}
