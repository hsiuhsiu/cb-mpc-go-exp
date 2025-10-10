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
)

// ECDSA2PKey is a type alias for *C.cbmpc_ecdsa2p_key
type ECDSA2PKey = *C.cbmpc_ecdsa2p_key

// ECDSA2PKeyFree frees an ECDSA 2P key.
func ECDSA2PKeyFree(key ECDSA2PKey) {
	if key == nil {
		return
	}
	C.cbmpc_ecdsa2p_key_free(key)
}

// ECDSA2PKeyGetPublicKey extracts the public key from an ECDSA 2P key.
func ECDSA2PKeyGetPublicKey(key ECDSA2PKey) ([]byte, error) {
	if key == nil {
		return nil, errors.New("nil key")
	}

	var out C.cmem_t
	rc := C.cbmpc_ecdsa2p_key_get_public_key(key, &out)
	if rc != 0 {
		return nil, errors.New("failed to get public key")
	}
	return cmemToGoBytes(out), nil
}

// ECDSA2PKeyGetCurveNID gets the curve NID from an ECDSA 2P key.
func ECDSA2PKeyGetCurveNID(key ECDSA2PKey) (int, error) {
	if key == nil {
		return 0, errors.New("nil key")
	}

	var nid C.int
	rc := C.cbmpc_ecdsa2p_key_get_curve_nid(key, &nid)
	if rc != 0 {
		return 0, errors.New("failed to get curve NID")
	}
	return int(nid), nil
}

// ECDSA2PKeySerialize serializes an ECDSA 2P key to bytes.
func ECDSA2PKeySerialize(key ECDSA2PKey) ([]byte, error) {
	if key == nil {
		return nil, errors.New("nil key")
	}

	var out C.cmem_t
	rc := C.cbmpc_ecdsa2p_key_serialize(key, &out)
	if rc != 0 {
		return nil, errors.New("failed to serialize key")
	}
	return cmemToGoBytes(out), nil
}

// ECDSA2PKeyDeserialize deserializes an ECDSA 2P key from bytes.
func ECDSA2PKeyDeserialize(data []byte) (ECDSA2PKey, error) {
	if len(data) == 0 {
		return nil, errors.New("empty data")
	}

	dataMem := goBytesToCmem(data)
	var key ECDSA2PKey
	rc := C.cbmpc_ecdsa2p_key_deserialize(dataMem, &key)
	if rc != 0 {
		return nil, errors.New("failed to deserialize key")
	}
	return key, nil
}
