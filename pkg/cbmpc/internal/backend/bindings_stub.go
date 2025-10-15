//go:build !cgo || windows

package backend

import (
	"context"
	"unsafe"

	"github.com/coinbase/cb-mpc-go/pkg/cbmpc/kem"
)

// Stub implementations for non-CGO builds or Windows.
// These allow the package to compile but return ErrNotBuilt when called.
// Note: Curve, types, and error definitions are in separate files with `!windows` build tags,
// so they're available for non-CGO builds on Unix platforms.

type transport interface {
	Send(context.Context, uint32, []byte) error
	Receive(context.Context, uint32) ([]byte, error)
	ReceiveAll(context.Context, []uint32) (map[uint32][]byte, error)
}

// KEM is a type alias for kem.KEM.
// This allows the backend to use the public KEM interface without importing it everywhere.
type KEM = kem.KEM

func NewJob2P(transport, uint32, []string) (unsafe.Pointer, uintptr, error) {
	return nil, 0, ErrNotBuilt
}

func FreeJob2P(unsafe.Pointer, uintptr) {}

func NewJobMP(transport, uint32, []string) (unsafe.Pointer, uintptr, error) {
	return nil, 0, ErrNotBuilt
}

func FreeJobMP(unsafe.Pointer, uintptr) {}

func AgreeRandom2P(unsafe.Pointer, int) ([]byte, error) {
	return nil, ErrNotBuilt
}

func AgreeRandomMP(unsafe.Pointer, int) ([]byte, error) {
	return nil, ErrNotBuilt
}

func WeakMultiAgreeRandom(unsafe.Pointer, int) ([]byte, error) {
	return nil, ErrNotBuilt
}

func MultiPairwiseAgreeRandom(unsafe.Pointer, int) ([][]byte, error) {
	return nil, ErrNotBuilt
}

// ECDSA2PKey is a stub type for non-CGO builds
type ECDSA2PKey = unsafe.Pointer

func ECDSA2PKeyFree(ECDSA2PKey) {}

func ECDSA2PKeyGetPublicKey(ECDSA2PKey) ([]byte, error) {
	return nil, ErrNotBuilt
}

func ECDSA2PKeyGetCurve(ECDSA2PKey) (Curve, error) {
	return Unknown, ErrNotBuilt
}

func ECDSA2PKeySerialize(ECDSA2PKey) ([]byte, error) {
	return nil, ErrNotBuilt
}

func ECDSA2PKeyDeserialize([]byte) (ECDSA2PKey, error) {
	return nil, ErrNotBuilt
}

func ECDSA2PDKG(unsafe.Pointer, int) (ECDSA2PKey, error) {
	return nil, ErrNotBuilt
}

func ECDSA2PRefresh(unsafe.Pointer, ECDSA2PKey) (ECDSA2PKey, error) {
	return nil, ErrNotBuilt
}

func ECDSA2PSign(unsafe.Pointer, ECDSA2PKey, []byte, []byte) ([]byte, []byte, error) {
	return nil, nil, ErrNotBuilt
}

func ECDSA2PSignBatch(unsafe.Pointer, ECDSA2PKey, []byte, [][]byte) ([]byte, [][]byte, error) {
	return nil, nil, ErrNotBuilt
}

func ECDSA2PSignWithGlobalAbort(unsafe.Pointer, ECDSA2PKey, []byte, []byte) ([]byte, []byte, error) {
	return nil, nil, ErrNotBuilt
}

func ECDSA2PSignWithGlobalAbortBatch(unsafe.Pointer, ECDSA2PKey, []byte, [][]byte) ([]byte, [][]byte, error) {
	return nil, nil, ErrNotBuilt
}

func PVEEncrypt(KEM, []byte, []byte, int, []byte) ([]byte, error) {
	return nil, ErrNotBuilt
}

func PVEDecrypt(KEM, unsafe.Pointer, []byte, []byte, []byte, int) ([]byte, error) {
	return nil, ErrNotBuilt
}

func PVEGetLabel([]byte) ([]byte, error) {
	return nil, ErrNotBuilt
}

func ScalarFromBytes([]byte) (unsafe.Pointer, error) {
	return nil, ErrNotBuilt
}

func ScalarFromString(string) (unsafe.Pointer, error) {
	return nil, ErrNotBuilt
}

func ScalarToBytes(unsafe.Pointer) ([]byte, error) {
	return nil, ErrNotBuilt
}

func ScalarFree(unsafe.Pointer) {}

// ECCPoint is a stub type for non-CGO builds
type ECCPoint = unsafe.Pointer

func ECCPointFromBytes(int, []byte) (ECCPoint, error) {
	return nil, ErrNotBuilt
}

func ECCPointToBytes(ECCPoint) ([]byte, error) {
	return nil, ErrNotBuilt
}

func ECCPointFree(ECCPoint) {}

func ECCPointGetCurve(ECCPoint) Curve {
	return Unknown
}

// ECElGamalCommitment is a stub type for non-CGO builds
type ECElGamalCommitment = unsafe.Pointer

func ECElGamalCommitmentNew(ECCPoint, ECCPoint) (ECElGamalCommitment, error) {
	return nil, ErrNotBuilt
}

func ECElGamalCommitmentToBytes(ECElGamalCommitment) ([]byte, error) {
	return nil, ErrNotBuilt
}

func ECElGamalCommitmentFromBytes(int, []byte) (ECElGamalCommitment, error) {
	return nil, ErrNotBuilt
}

func ECElGamalCommitmentGetL(ECElGamalCommitment) (ECCPoint, error) {
	return nil, ErrNotBuilt
}

func ECElGamalCommitmentGetR(ECElGamalCommitment) (ECCPoint, error) {
	return nil, ErrNotBuilt
}

func ECElGamalCommitmentFree(ECElGamalCommitment) {}

func ECElGamalCommitmentMake(ECCPoint, []byte, []byte) (ECElGamalCommitment, error) {
	return nil, ErrNotBuilt
}

func PVEGetQPoint([]byte) (ECCPoint, error) {
	return nil, ErrNotBuilt
}

func PVEVerifyWithPoint(KEM, []byte, []byte, ECCPoint, []byte) error {
	return ErrNotBuilt
}

// Removed SetKEM in favor of passing KEM directly per call.

func RegisterHandle(any) unsafe.Pointer {
	return nil
}

func FreeHandle(unsafe.Pointer) {}

func UCDLProve(ECCPoint, []byte, []byte, uint64) ([]byte, error) {
	return nil, ErrNotBuilt
}

func UCDLVerify([]byte, ECCPoint, []byte, uint64) error {
	return ErrNotBuilt
}

func UCBatchDLProve([]ECCPoint, [][]byte, []byte, uint64) ([]byte, error) {
	return nil, ErrNotBuilt
}

func UCBatchDLVerify([]byte, []ECCPoint, []byte, uint64) error {
	return ErrNotBuilt
}

func DHProve(ECCPoint, ECCPoint, ECCPoint, []byte, []byte, uint64) ([]byte, error) {
	return nil, ErrNotBuilt
}

func DHVerify([]byte, ECCPoint, ECCPoint, ECCPoint, []byte, uint64) error {
	return ErrNotBuilt
}

func UCElGamalComProve(ECCPoint, ECElGamalCommitment, []byte, []byte, []byte, uint64) ([]byte, error) {
	return nil, ErrNotBuilt
}

func UCElGamalComVerify([]byte, ECCPoint, ECElGamalCommitment, []byte, uint64) error {
	return ErrNotBuilt
}

func ElGamalComPubShareEquProve(ECCPoint, ECCPoint, ECElGamalCommitment, []byte, []byte, uint64) ([]byte, error) {
	return nil, ErrNotBuilt
}

func ElGamalComPubShareEquVerify([]byte, ECCPoint, ECCPoint, ECElGamalCommitment, []byte, uint64) error {
	return ErrNotBuilt
}

func ElGamalComMultProve(ECCPoint, ECElGamalCommitment, ECElGamalCommitment, ECElGamalCommitment, []byte, []byte, []byte, []byte, uint64) ([]byte, error) {
	return nil, ErrNotBuilt
}

func ElGamalComMultVerify([]byte, ECCPoint, ECElGamalCommitment, ECElGamalCommitment, ECElGamalCommitment, []byte, uint64) error {
	return ErrNotBuilt
}

func UCElGamalComMultPrivateScalarProve(ECCPoint, ECElGamalCommitment, ECElGamalCommitment, []byte, []byte, []byte, uint64) ([]byte, error) {
	return nil, ErrNotBuilt
}

func UCElGamalComMultPrivateScalarVerify([]byte, ECCPoint, ECElGamalCommitment, ECElGamalCommitment, []byte, uint64) error {
	return ErrNotBuilt
}

// ECDSAMPKey is a stub type for non-CGO builds
type ECDSAMPKey = unsafe.Pointer

func ECDSAMPKeyFree(ECDSAMPKey) {}

func ECDSAMPKeyGetPublicKey(ECDSAMPKey) ([]byte, error) {
	return nil, ErrNotBuilt
}

func ECDSAMPKeyGetCurve(ECDSAMPKey) (Curve, error) {
	return Unknown, ErrNotBuilt
}

func ECDSAMPKeySerialize(ECDSAMPKey) ([]byte, error) {
	return nil, ErrNotBuilt
}

func ECDSAMPKeyDeserialize([]byte) (ECDSAMPKey, error) {
	return nil, ErrNotBuilt
}

func ECDSAMP_DKG(unsafe.Pointer, int) (ECDSAMPKey, []byte, error) {
	return nil, nil, ErrNotBuilt
}

func ECDSAMPRefresh(unsafe.Pointer, ECDSAMPKey, []byte) (ECDSAMPKey, []byte, error) {
	return nil, nil, ErrNotBuilt
}

func ECDSAMPSign(unsafe.Pointer, ECDSAMPKey, []byte, int) ([]byte, error) {
	return nil, ErrNotBuilt
}

// Schnorr2PKey is a stub type for non-CGO builds
type Schnorr2PKey = unsafe.Pointer

func Schnorr2PDKG(unsafe.Pointer, int) (Schnorr2PKey, error) {
	return nil, ErrNotBuilt
}

func Schnorr2PKeyFree(Schnorr2PKey) {}

func Schnorr2PKeySerialize(Schnorr2PKey) ([]byte, error) {
	return nil, ErrNotBuilt
}

func Schnorr2PKeyDeserialize([]byte) (Schnorr2PKey, error) {
	return nil, ErrNotBuilt
}

func Schnorr2PKeyGetPublicKey(Schnorr2PKey) ([]byte, error) {
	return nil, ErrNotBuilt
}

func Schnorr2PKeyGetCurve(Schnorr2PKey) (int, error) {
	return 0, ErrNotBuilt
}

// SchnorrVariant is a stub type for non-CGO builds
type SchnorrVariant int

const (
	SchnorrVariantEdDSA  SchnorrVariant = 0
	SchnorrVariantBIP340 SchnorrVariant = 1
)

func Schnorr2PSign(unsafe.Pointer, Schnorr2PKey, []byte, SchnorrVariant) ([]byte, error) {
	return nil, ErrNotBuilt
}

func Schnorr2PSignBatch(unsafe.Pointer, Schnorr2PKey, [][]byte, SchnorrVariant) ([][]byte, error) {
	return nil, ErrNotBuilt
}

func SchnorrMPSign(unsafe.Pointer, ECDSAMPKey, []byte, int, SchnorrVariant) ([]byte, error) {
	return nil, ErrNotBuilt
}

func SchnorrMPSignBatch(unsafe.Pointer, ECDSAMPKey, [][]byte, int, SchnorrVariant) ([][]byte, error) {
	return nil, ErrNotBuilt
}

// Curve operations stubs
func CurveRandomScalar(int) ([]byte, error) {
	return nil, ErrNotBuilt
}

func CurveGetGenerator(int) (ECCPoint, error) {
	return nil, ErrNotBuilt
}

func CurveMulGenerator(int, []byte) (ECCPoint, error) {
	return nil, ErrNotBuilt
}

func ECCPointMul(ECCPoint, []byte) (ECCPoint, error) {
	return nil, ErrNotBuilt
}

func ECCPointAdd(ECCPoint, ECCPoint) (ECCPoint, error) {
	return nil, ErrNotBuilt
}

func ScalarAdd([]byte, []byte, int) ([]byte, error) {
	return nil, ErrNotBuilt
}
