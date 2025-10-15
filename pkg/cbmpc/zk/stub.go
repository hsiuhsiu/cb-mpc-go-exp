//go:build !cgo || windows

package zk

import (
	"github.com/coinbase/cb-mpc-go/pkg/cbmpc"
	"github.com/coinbase/cb-mpc-go/pkg/cbmpc/internal/backend"
	"github.com/coinbase/cb-mpc-go/pkg/cbmpc/paillier"
)

// =====================
// ValidPaillier ZK proof stubs
// =====================

// ValidPaillierProof represents a zero-knowledge proof that a Paillier key is well-formed (stub).
type ValidPaillierProof []byte

// ValidPaillierProveParams contains parameters for Valid_Paillier proof generation (stub).
type ValidPaillierProveParams struct {
	Paillier  *paillier.Paillier
	SessionID cbmpc.SessionID
	Aux       uint64
}

// ProveValidPaillier is a stub that returns ErrNotBuilt.
func ProveValidPaillier(*ValidPaillierProveParams) (ValidPaillierProof, error) {
	return nil, backend.ErrNotBuilt
}

// ValidPaillierVerifyParams contains parameters for Valid_Paillier proof verification (stub).
type ValidPaillierVerifyParams struct {
	Proof     ValidPaillierProof
	Paillier  *paillier.Paillier
	SessionID cbmpc.SessionID
	Aux       uint64
}

// VerifyValidPaillier is a stub that returns ErrNotBuilt.
func VerifyValidPaillier(*ValidPaillierVerifyParams) error {
	return backend.ErrNotBuilt
}

// =====================
// PaillierZero ZK proof stubs
// =====================

// PaillierZeroProof represents a zero-knowledge proof that a Paillier ciphertext encrypts zero (stub).
type PaillierZeroProof []byte

// PaillierZeroProveParams contains parameters for Paillier_Zero proof generation (stub).
type PaillierZeroProveParams struct {
	Paillier  *paillier.Paillier
	C         []byte
	R         []byte
	SessionID cbmpc.SessionID
	Aux       uint64
}

// ProvePaillierZero is a stub that returns ErrNotBuilt.
func ProvePaillierZero(*PaillierZeroProveParams) (PaillierZeroProof, error) {
	return nil, backend.ErrNotBuilt
}

// PaillierZeroVerifyParams contains parameters for Paillier_Zero proof verification (stub).
type PaillierZeroVerifyParams struct {
	Proof     PaillierZeroProof
	Paillier  *paillier.Paillier
	C         []byte
	SessionID cbmpc.SessionID
	Aux       uint64
}

// VerifyPaillierZero is a stub that returns ErrNotBuilt.
func VerifyPaillierZero(*PaillierZeroVerifyParams) error {
	return backend.ErrNotBuilt
}

// =====================
// TwoPaillierEqual ZK proof stubs
// =====================

// TwoPaillierEqualProof represents a zero-knowledge proof that two Paillier ciphertexts encrypt the same plaintext (stub).
type TwoPaillierEqualProof []byte

// TwoPaillierEqualProveParams contains parameters for Two_Paillier_Equal proof generation (stub).
type TwoPaillierEqualProveParams struct {
	Q         []byte
	P0        *paillier.Paillier
	C0        []byte
	P1        *paillier.Paillier
	C1        []byte
	X         []byte
	R0        []byte
	R1        []byte
	SessionID cbmpc.SessionID
	Aux       uint64
}

// ProveTwoPaillierEqual is a stub that returns ErrNotBuilt.
func ProveTwoPaillierEqual(*TwoPaillierEqualProveParams) (TwoPaillierEqualProof, error) {
	return nil, backend.ErrNotBuilt
}

// TwoPaillierEqualVerifyParams contains parameters for Two_Paillier_Equal proof verification (stub).
type TwoPaillierEqualVerifyParams struct {
	Proof     TwoPaillierEqualProof
	Q         []byte
	P0        *paillier.Paillier
	C0        []byte
	P1        *paillier.Paillier
	C1        []byte
	SessionID cbmpc.SessionID
	Aux       uint64
}

// VerifyTwoPaillierEqual is a stub that returns ErrNotBuilt.
func VerifyTwoPaillierEqual(*TwoPaillierEqualVerifyParams) error {
	return backend.ErrNotBuilt
}

// =====================
// PaillierRangeExpSlack ZK proof stubs
// =====================

// PaillierRangeExpSlackProof represents a zero-knowledge proof that a Paillier ciphertext encrypts a value in range (stub).
type PaillierRangeExpSlackProof []byte

// PaillierRangeExpSlackProveParams contains parameters for Paillier_Range_Exp_Slack proof generation (stub).
type PaillierRangeExpSlackProveParams struct {
	Paillier  *paillier.Paillier
	Q         []byte
	C         []byte
	X         []byte
	R         []byte
	SessionID cbmpc.SessionID
	Aux       uint64
}

// ProvePaillierRangeExpSlack is a stub that returns ErrNotBuilt.
func ProvePaillierRangeExpSlack(*PaillierRangeExpSlackProveParams) (PaillierRangeExpSlackProof, error) {
	return nil, backend.ErrNotBuilt
}

// PaillierRangeExpSlackVerifyParams contains parameters for Paillier_Range_Exp_Slack proof verification (stub).
type PaillierRangeExpSlackVerifyParams struct {
	Proof     PaillierRangeExpSlackProof
	Paillier  *paillier.Paillier
	Q         []byte
	C         []byte
	SessionID cbmpc.SessionID
	Aux       uint64
}

// VerifyPaillierRangeExpSlack is a stub that returns ErrNotBuilt.
func VerifyPaillierRangeExpSlack(*PaillierRangeExpSlackVerifyParams) error {
	return backend.ErrNotBuilt
}
