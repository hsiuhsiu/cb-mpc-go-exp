//go:build cgo && !windows

package bindings

/*
#include <stdlib.h>
#include "capi.h"
#include "cbmpc/core/cmem.h"
*/
import "C"

import (
	"errors"
	"unsafe"
)

// AgreeRandom2P is a C binding wrapper for the two-party agree random protocol.
func AgreeRandom2P(cj unsafe.Pointer, bitlen int) ([]byte, error) {
	if cj == nil {
		return nil, errors.New("nil job")
	}
	var out C.cmem_t
	rc := C.cbmpc_agree_random_2p((*C.cbmpc_job2p)(cj), C.int(bitlen), &out)
	if rc != 0 {
		return nil, errors.New("agree_random failed")
	}
	return cmemToGoBytes(out), nil
}

// AgreeRandomMP is a C binding wrapper for the multi-party agree random protocol.
func AgreeRandomMP(cj unsafe.Pointer, bitlen int) ([]byte, error) {
	if cj == nil {
		return nil, errors.New("nil job")
	}
	var out C.cmem_t
	rc := C.cbmpc_multi_agree_random((*C.cbmpc_jobmp)(cj), C.int(bitlen), &out)
	if rc != 0 {
		return nil, errors.New("multi_agree_random failed")
	}
	return cmemToGoBytes(out), nil
}

// WeakMultiAgreeRandom is a C binding wrapper for the weak multi-party agree random protocol.
func WeakMultiAgreeRandom(cj unsafe.Pointer, bitlen int) ([]byte, error) {
	if cj == nil {
		return nil, errors.New("nil job")
	}
	var out C.cmem_t
	rc := C.cbmpc_weak_multi_agree_random((*C.cbmpc_jobmp)(cj), C.int(bitlen), &out)
	if rc != 0 {
		return nil, errors.New("weak_multi_agree_random failed")
	}
	return cmemToGoBytes(out), nil
}

// MultiPairwiseAgreeRandom is a C binding wrapper for the multi-party pairwise agree random protocol.
func MultiPairwiseAgreeRandom(cj unsafe.Pointer, bitlen int) ([][]byte, error) {
	if cj == nil {
		return nil, errors.New("nil job")
	}
	var out C.cmems_t
	rc := C.cbmpc_multi_pairwise_agree_random((*C.cbmpc_jobmp)(cj), C.int(bitlen), &out)
	if rc != 0 {
		return nil, errors.New("multi_pairwise_agree_random failed")
	}
	return cmemsToGoByteSlices(out), nil
}

// ECDSA2PKeyGetPublicKey extracts the public key from a serialized ECDSA 2P key.
func ECDSA2PKeyGetPublicKey(serializedKey []byte) ([]byte, error) {
	if len(serializedKey) == 0 {
		return nil, errors.New("empty key")
	}
	keyMem := goBytesToCmem(serializedKey)
	if keyMem.data != nil {
		defer C.free(unsafe.Pointer(keyMem.data))
	}

	var out C.cmem_t
	rc := C.cbmpc_ecdsa2p_key_get_public_key(keyMem, &out)
	if rc != 0 {
		return nil, errors.New("failed to get public key")
	}
	return cmemToGoBytes(out), nil
}

// ECDSA2PKeyGetCurveNID gets the curve NID from a serialized ECDSA 2P key.
func ECDSA2PKeyGetCurveNID(serializedKey []byte) (int, error) {
	if len(serializedKey) == 0 {
		return 0, errors.New("empty key")
	}
	keyMem := goBytesToCmem(serializedKey)
	if keyMem.data != nil {
		defer C.free(unsafe.Pointer(keyMem.data))
	}

	var nid C.int
	rc := C.cbmpc_ecdsa2p_key_get_curve_nid(keyMem, &nid)
	if rc != 0 {
		return 0, errors.New("failed to get curve NID")
	}
	return int(nid), nil
}

// ECDSA2PDKG is a C binding wrapper for 2-party ECDSA distributed key generation.
func ECDSA2PDKG(cj unsafe.Pointer, curveNID int) ([]byte, error) {
	if cj == nil {
		return nil, errors.New("nil job")
	}
	var out C.cmem_t
	rc := C.cbmpc_ecdsa2p_dkg((*C.cbmpc_job2p)(cj), C.int(curveNID), &out)
	if rc != 0 {
		return nil, errors.New("ecdsa2p_dkg failed")
	}
	return cmemToGoBytes(out), nil
}

// ECDSA2PRefresh is a C binding wrapper for 2-party ECDSA key refresh.
func ECDSA2PRefresh(cj unsafe.Pointer, keyIn []byte) ([]byte, error) {
	if cj == nil {
		return nil, errors.New("nil job")
	}
	if len(keyIn) == 0 {
		return nil, errors.New("empty key")
	}
	keyMem := goBytesToCmem(keyIn)
	if keyMem.data != nil {
		defer C.free(unsafe.Pointer(keyMem.data))
	}

	var out C.cmem_t
	rc := C.cbmpc_ecdsa2p_refresh((*C.cbmpc_job2p)(cj), keyMem, &out)
	if rc != 0 {
		return nil, errors.New("ecdsa2p_refresh failed")
	}
	return cmemToGoBytes(out), nil
}

// ECDSA2PSign is a C binding wrapper for 2-party ECDSA signing.
func ECDSA2PSign(cj unsafe.Pointer, sidIn, key, msg []byte) ([]byte, []byte, error) {
	if cj == nil {
		return nil, nil, errors.New("nil job")
	}
	if len(key) == 0 {
		return nil, nil, errors.New("empty key")
	}
	if len(msg) == 0 {
		return nil, nil, errors.New("empty message")
	}

	sidMem := goBytesToCmem(sidIn)
	if sidMem.data != nil {
		defer C.free(unsafe.Pointer(sidMem.data))
	}
	keyMem := goBytesToCmem(key)
	if keyMem.data != nil {
		defer C.free(unsafe.Pointer(keyMem.data))
	}
	msgMem := goBytesToCmem(msg)
	if msgMem.data != nil {
		defer C.free(unsafe.Pointer(msgMem.data))
	}

	var sidOut, sigOut C.cmem_t
	rc := C.cbmpc_ecdsa2p_sign((*C.cbmpc_job2p)(cj), sidMem, keyMem, msgMem, &sidOut, &sigOut)
	if rc != 0 {
		return nil, nil, errors.New("ecdsa2p_sign failed")
	}

	return cmemToGoBytes(sidOut), cmemToGoBytes(sigOut), nil
}
