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

func ECDSA2PKeyFree(unsafe.Pointer) {}

func ECDSA2PKeyGetPublicKey(unsafe.Pointer) ([]byte, error) {
	return nil, ErrNotBuilt
}

func ECDSA2PKeyGetCurveNID(unsafe.Pointer) (int, error) {
	return 0, ErrNotBuilt
}

func ECDSA2PKeySerialize(unsafe.Pointer) ([]byte, error) {
	return nil, ErrNotBuilt
}

func ECDSA2PKeyDeserialize([]byte) (unsafe.Pointer, error) {
	return nil, ErrNotBuilt
}

func ECDSA2PDKG(unsafe.Pointer, int) (unsafe.Pointer, error) {
	return nil, ErrNotBuilt
}

func ECDSA2PRefresh(unsafe.Pointer, unsafe.Pointer) (unsafe.Pointer, error) {
	return nil, ErrNotBuilt
}

func ECDSA2PSign(unsafe.Pointer, unsafe.Pointer, []byte, []byte) ([]byte, []byte, error) {
	return nil, nil, ErrNotBuilt
}
