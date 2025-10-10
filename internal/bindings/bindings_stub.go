//go:build !cgo || windows

package bindings

import (
	"context"
	"unsafe"
)

// Stub implementations for non-CGO builds or Windows.
// These allow the package to compile but return ErrNotBuilt when called.

type transport interface {
	Send(context.Context, uint32, []byte) error
	Receive(context.Context, uint32) ([]byte, error)
	ReceiveAll(context.Context, []uint32) (map[uint32][]byte, error)
}

// KEM is the KEM interface stub for non-CGO builds
type KEM interface {
	Encapsulate(ek []byte, rho [32]byte) (ct, ss []byte, err error)
	Decapsulate(skHandle any, ct []byte) (ss []byte, err error)
	DerivePub(skRef []byte) ([]byte, error)
}

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

func ECDSA2PKeyGetCurveNID(ECDSA2PKey) (int, error) {
	return 0, ErrNotBuilt
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

func PVEEncrypt([]byte, []byte, int, []byte) ([]byte, error) {
	return nil, ErrNotBuilt
}

func PVEDecrypt(unsafe.Pointer, []byte, []byte, []byte, int) ([]byte, error) {
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

func ECCPointGetCurveNID(ECCPoint) int {
	return 0
}

func PVEGetQPoint([]byte) (ECCPoint, error) {
	return nil, ErrNotBuilt
}

func PVEVerifyWithPoint([]byte, []byte, ECCPoint, []byte) error {
	return ErrNotBuilt
}

// SetKEM is a stub for setting the KEM for the current goroutine
func SetKEM(KEM) func() {
	return func() {}
}

func RegisterHandle(any) unsafe.Pointer {
	return nil
}

func FreeHandle(unsafe.Pointer) {}
