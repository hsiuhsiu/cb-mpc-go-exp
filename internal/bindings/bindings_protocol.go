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

// ECDSA2PDKG is a C binding wrapper for 2-party ECDSA distributed key generation.
func ECDSA2PDKG(cj unsafe.Pointer, curveNID int) (unsafe.Pointer, error) {
	if cj == nil {
		return nil, errors.New("nil job")
	}

	var key *C.cbmpc_ecdsa2p_key
	rc := C.cbmpc_ecdsa2p_dkg((*C.cbmpc_job2p)(cj), C.int(curveNID), &key)
	if rc != 0 {
		return nil, errors.New("ecdsa2p_dkg failed")
	}
	return unsafe.Pointer(key), nil
}

// ECDSA2PRefresh is a C binding wrapper for 2-party ECDSA key refresh.
func ECDSA2PRefresh(cj, key unsafe.Pointer) (unsafe.Pointer, error) {
	if cj == nil {
		return nil, errors.New("nil job")
	}
	if key == nil {
		return nil, errors.New("nil key")
	}

	var newKey *C.cbmpc_ecdsa2p_key
	rc := C.cbmpc_ecdsa2p_refresh((*C.cbmpc_job2p)(cj), (*C.cbmpc_ecdsa2p_key)(key), &newKey)
	if rc != 0 {
		return nil, errors.New("ecdsa2p_refresh failed")
	}
	return unsafe.Pointer(newKey), nil
}

// ECDSA2PSign is a C binding wrapper for 2-party ECDSA signing.
func ECDSA2PSign(cj, key unsafe.Pointer, sidIn, msg []byte) ([]byte, []byte, error) {
	if cj == nil {
		return nil, nil, errors.New("nil job")
	}
	if key == nil {
		return nil, nil, errors.New("nil key")
	}
	if len(msg) == 0 {
		return nil, nil, errors.New("empty message")
	}

	sidMem := goBytesToCmem(sidIn)
	msgMem := goBytesToCmem(msg)

	var sidOut, sigOut C.cmem_t
	rc := C.cbmpc_ecdsa2p_sign((*C.cbmpc_job2p)(cj), sidMem, (*C.cbmpc_ecdsa2p_key)(key), msgMem, &sidOut, &sigOut)
	if rc != 0 {
		return nil, nil, errors.New("ecdsa2p_sign failed")
	}

	return cmemToGoBytes(sidOut), cmemToGoBytes(sigOut), nil
}
