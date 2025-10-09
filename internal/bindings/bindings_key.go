//go:build cgo && !windows

package bindings

/*
#include <stdlib.h>
#include "ctypes.h"
#include "cbmpc/core/cmem.h"
*/
import "C"

import (
	"errors"
	"unsafe"
)

// ECDSA2PKeyFree frees an ECDSA 2P key.
func ECDSA2PKeyFree(key unsafe.Pointer) {
	if key == nil {
		return
	}
	C.cbmpc_ecdsa2p_key_free((*C.cbmpc_ecdsa2p_key)(key))
}

// ECDSA2PKeyGetPublicKey extracts the public key from an ECDSA 2P key.
func ECDSA2PKeyGetPublicKey(key unsafe.Pointer) ([]byte, error) {
	if key == nil {
		return nil, errors.New("nil key")
	}

	var out C.cmem_t
	rc := C.cbmpc_ecdsa2p_key_get_public_key((*C.cbmpc_ecdsa2p_key)(key), &out)
	if rc != 0 {
		return nil, errors.New("failed to get public key")
	}
	return cmemToGoBytes(out), nil
}

// ECDSA2PKeyGetCurveNID gets the curve NID from an ECDSA 2P key.
func ECDSA2PKeyGetCurveNID(key unsafe.Pointer) (int, error) {
	if key == nil {
		return 0, errors.New("nil key")
	}

	var nid C.int
	rc := C.cbmpc_ecdsa2p_key_get_curve_nid((*C.cbmpc_ecdsa2p_key)(key), &nid)
	if rc != 0 {
		return 0, errors.New("failed to get curve NID")
	}
	return int(nid), nil
}

// ECDSA2PKeySerialize serializes an ECDSA 2P key to bytes.
func ECDSA2PKeySerialize(key unsafe.Pointer) ([]byte, error) {
	if key == nil {
		return nil, errors.New("nil key")
	}

	var out C.cmem_t
	rc := C.cbmpc_ecdsa2p_key_serialize((*C.cbmpc_ecdsa2p_key)(key), &out)
	if rc != 0 {
		return nil, errors.New("failed to serialize key")
	}
	return cmemToGoBytes(out), nil
}

// ECDSA2PKeyDeserialize deserializes an ECDSA 2P key from bytes.
func ECDSA2PKeyDeserialize(data []byte) (unsafe.Pointer, error) {
	if len(data) == 0 {
		return nil, errors.New("empty data")
	}

	dataMem := goBytesToCmem(data)
	var key *C.cbmpc_ecdsa2p_key
	rc := C.cbmpc_ecdsa2p_key_deserialize(dataMem, &key)
	if rc != 0 {
		return nil, errors.New("failed to deserialize key")
	}
	return unsafe.Pointer(key), nil
}
