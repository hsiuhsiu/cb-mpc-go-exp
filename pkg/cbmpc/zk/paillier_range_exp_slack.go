//go:build cgo && !windows

package zk

import (
	"errors"

	"github.com/coinbase/cb-mpc-go/pkg/cbmpc"
	"github.com/coinbase/cb-mpc-go/pkg/cbmpc/internal/backend"
	"github.com/coinbase/cb-mpc-go/pkg/cbmpc/paillier"
)

// PaillierRangeExpSlackProof represents a zero-knowledge proof that a Paillier ciphertext
// encrypts a value within a valid range with slack.
// This proof combines range checking with Paillier encryption, ensuring that the encrypted
// value is within acceptable bounds without revealing the value itself.
//
// PaillierRangeExpSlackProof is a value type ([]byte) that can be safely copied, passed across goroutines,
// and serialized without resource management concerns. There is no Close() method or finalizer.
type PaillierRangeExpSlackProof []byte

// PaillierRangeExpSlackProveParams contains parameters for Paillier_Range_Exp_Slack proof generation.
// This proves that a Paillier ciphertext encrypts a value within a valid range.
type PaillierRangeExpSlackProveParams struct {
	Paillier  *paillier.Paillier // The Paillier key used for encryption (must have private key)
	Q         []byte             // Modulus q (for range proofs)
	C         []byte             // The ciphertext to prove is in range
	X         []byte             // The plaintext value (must be in valid range)
	R         []byte             // The randomness used to create the ciphertext
	SessionID cbmpc.SessionID    // Session identifier for security
	Aux       uint64             // Auxiliary data (e.g., party identifier)
}

// ProvePaillierRangeExpSlack creates a Paillier_Range_Exp_Slack proof for proving that
// a ciphertext encrypts a value within a valid range with slack.
// The Paillier instance must have a private key.
// Returns the proof as bytes - no Close() required, safe to copy and serialize.
// See cb-mpc/src/cbmpc/zk/zk_paillier.h for protocol details.
func ProvePaillierRangeExpSlack(params *PaillierRangeExpSlackProveParams) (PaillierRangeExpSlackProof, error) {
	if params == nil {
		return nil, errors.New("nil params")
	}
	if params.Paillier == nil {
		return nil, errors.New("nil paillier")
	}
	if len(params.Q) == 0 {
		return nil, errors.New("empty modulus q")
	}
	if len(params.C) == 0 {
		return nil, errors.New("empty ciphertext")
	}
	if len(params.X) == 0 {
		return nil, errors.New("empty plaintext")
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

	proofBytes, err := backend.PaillierRangeExpSlackProve(
		handle,
		params.Q,
		params.C,
		params.X,
		params.R,
		params.SessionID.Bytes(),
		params.Aux,
	)
	if err != nil {
		return nil, cbmpc.RemapError(err)
	}

	return PaillierRangeExpSlackProof(proofBytes), nil
}

// PaillierRangeExpSlackVerifyParams contains parameters for Paillier_Range_Exp_Slack proof verification.
type PaillierRangeExpSlackVerifyParams struct {
	Proof     PaillierRangeExpSlackProof // The proof to verify
	Paillier  *paillier.Paillier         // The Paillier key (can be public key only)
	Q         []byte                     // Modulus q (must match the one used in Prove)
	C         []byte                     // The ciphertext claimed to be in range
	SessionID cbmpc.SessionID            // Session identifier (must match the one used in Prove)
	Aux       uint64                     // Auxiliary data (must match the one used in Prove)
}

// VerifyPaillierRangeExpSlack verifies a Paillier_Range_Exp_Slack proof.
// The Paillier instance can be a public key only (no private key required for verification).
// See cb-mpc/src/cbmpc/zk/zk_paillier.h for protocol details.
func VerifyPaillierRangeExpSlack(params *PaillierRangeExpSlackVerifyParams) error {
	if params == nil {
		return errors.New("nil params")
	}
	if len(params.Proof) == 0 {
		return errors.New("empty proof")
	}
	if params.Paillier == nil {
		return errors.New("nil paillier")
	}
	if len(params.Q) == 0 {
		return errors.New("empty modulus q")
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

	err := backend.PaillierRangeExpSlackVerify(
		[]byte(params.Proof),
		handle,
		params.Q,
		params.C,
		params.SessionID.Bytes(),
		params.Aux,
	)
	if err != nil {
		return cbmpc.RemapError(err)
	}

	return nil
}
