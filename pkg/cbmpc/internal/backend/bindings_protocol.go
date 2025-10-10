//go:build cgo && !windows

package backend

/*
#include <stdlib.h>
#include "capi.h"
#include "cbmpc/core/cmem.h"
*/
import "C"

import (
	"errors"
	"fmt"
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
func ECDSA2PDKG(cj unsafe.Pointer, curveNID int) (ECDSA2PKey, error) {
	if cj == nil {
		return nil, errors.New("nil job")
	}

	var key ECDSA2PKey
	rc := C.cbmpc_ecdsa2p_dkg((*C.cbmpc_job2p)(cj), C.int(curveNID), &key)
	if rc != 0 {
		return nil, errors.New("ecdsa2p_dkg failed")
	}
	return key, nil
}

// ECDSA2PRefresh is a C binding wrapper for 2-party ECDSA key refresh.
func ECDSA2PRefresh(cj unsafe.Pointer, key ECDSA2PKey) (ECDSA2PKey, error) {
	if cj == nil {
		return nil, errors.New("nil job")
	}
	if key == nil {
		return nil, errors.New("nil key")
	}

	var newKey ECDSA2PKey
	rc := C.cbmpc_ecdsa2p_refresh((*C.cbmpc_job2p)(cj), key, &newKey)
	if rc != 0 {
		return nil, errors.New("ecdsa2p_refresh failed")
	}
	return newKey, nil
}

// ECDSA2PSign is a C binding wrapper for 2-party ECDSA signing.
func ECDSA2PSign(cj unsafe.Pointer, key ECDSA2PKey, sidIn, msg []byte) ([]byte, []byte, error) {
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
	rc := C.cbmpc_ecdsa2p_sign((*C.cbmpc_job2p)(cj), sidMem, key, msgMem, &sidOut, &sigOut)
	if rc != 0 {
		return nil, nil, errors.New("ecdsa2p_sign failed")
	}

	return cmemToGoBytes(sidOut), cmemToGoBytes(sigOut), nil
}

// ECDSA2PSignBatch signs multiple messages with an ECDSA 2P key (batch mode).
func ECDSA2PSignBatch(cj unsafe.Pointer, key ECDSA2PKey, sidIn []byte, msgs [][]byte) ([]byte, [][]byte, error) {
	if cj == nil {
		return nil, nil, errors.New("nil job")
	}
	if key == nil {
		return nil, nil, errors.New("nil key")
	}
	if len(msgs) == 0 {
		return nil, nil, errors.New("empty messages")
	}

	sidMem := goBytesToCmem(sidIn)
	msgsMem := goBytesSliceToCmems(msgs)
	defer freeCmems(msgsMem)

	var sidOut C.cmem_t
	var sigsOut C.cmems_t
	rc := C.cbmpc_ecdsa2p_sign_batch((*C.cbmpc_job2p)(cj), sidMem, key, msgsMem, &sidOut, &sigsOut)
	if rc != 0 {
		return nil, nil, fmt.Errorf("ecdsa2p_sign_batch failed with code %d (0x%x)", rc, rc)
	}

	return cmemToGoBytes(sidOut), cmemsToGoByteSlices(sigsOut), nil
}

// ECDSA2PSignWithGlobalAbort signs a message with an ECDSA 2P key using global abort mode.
// Returns ErrBitLeak if signature verification fails (indicates potential key leak).
func ECDSA2PSignWithGlobalAbort(cj unsafe.Pointer, key ECDSA2PKey, sidIn, msg []byte) ([]byte, []byte, error) {
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
	rc := C.cbmpc_ecdsa2p_sign_with_global_abort((*C.cbmpc_job2p)(cj), sidMem, key, msgMem, &sidOut, &sigOut)
	if rc != 0 {
		if C.uint(rc) == C.uint(E_ECDSA_2P_BIT_LEAK) {
			return nil, nil, ErrBitLeak
		}
		return nil, nil, errors.New("ecdsa2p_sign_with_global_abort failed")
	}

	return cmemToGoBytes(sidOut), cmemToGoBytes(sigOut), nil
}

// ECDSA2PSignWithGlobalAbortBatch signs multiple messages with an ECDSA 2P key using global abort mode (batch mode).
// Returns ErrBitLeak if signature verification fails (indicates potential key leak).
func ECDSA2PSignWithGlobalAbortBatch(cj unsafe.Pointer, key ECDSA2PKey, sidIn []byte, msgs [][]byte) ([]byte, [][]byte, error) {
	if cj == nil {
		return nil, nil, errors.New("nil job")
	}
	if key == nil {
		return nil, nil, errors.New("nil key")
	}
	if len(msgs) == 0 {
		return nil, nil, errors.New("empty messages")
	}

	sidMem := goBytesToCmem(sidIn)
	msgsMem := goBytesSliceToCmems(msgs)
	defer freeCmems(msgsMem)

	var sidOut C.cmem_t
	var sigsOut C.cmems_t
	rc := C.cbmpc_ecdsa2p_sign_with_global_abort_batch((*C.cbmpc_job2p)(cj), sidMem, key, msgsMem, &sidOut, &sigsOut)
	if rc != 0 {
		if C.uint(rc) == C.uint(E_ECDSA_2P_BIT_LEAK) {
			return nil, nil, ErrBitLeak
		}
		return nil, nil, fmt.Errorf("ecdsa2p_sign_with_global_abort_batch failed with code %d (0x%x)", rc, rc)
	}

	return cmemToGoBytes(sidOut), cmemsToGoByteSlices(sigsOut), nil
}
