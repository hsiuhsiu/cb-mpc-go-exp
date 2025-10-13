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
	"runtime"
	"unsafe"

	"github.com/coinbase/cb-mpc-go/pkg/cbmpc/kem"
)

// formatNativeErr formats a native error code with category and code fields.
func formatNativeErr(op string, rc C.int) error {
	u := uint32(rc)
	return fmt.Errorf("%s failed with code %d (0x%x, cat=0x%x, code=0x%x)", op, int(rc), u, (u>>16)&0xff, u&0xffff)
}

// AgreeRandom2P is a C binding wrapper for the two-party agree random protocol.
func AgreeRandom2P(cj unsafe.Pointer, bitlen int) ([]byte, error) {
	if cj == nil {
		return nil, errors.New("nil job")
	}
	var out C.cmem_t
	rc := C.cbmpc_agree_random_2p((*C.cbmpc_job2p)(cj), C.int(bitlen), &out)
	if rc != 0 {
		return nil, formatNativeErr("agree_random", rc)
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
		return nil, formatNativeErr("multi_agree_random", rc)
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
		return nil, formatNativeErr("weak_multi_agree_random", rc)
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
		return nil, formatNativeErr("multi_pairwise_agree_random", rc)
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
		return nil, formatNativeErr("ecdsa2p_dkg", rc)
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
		return nil, formatNativeErr("ecdsa2p_refresh", rc)
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

	// Copy inputs into C-allocated memory to avoid aliasing Go memory during CGO call
	sidMem := allocCmem(sidIn)
	defer freeCmem(sidMem)
	msgMem := allocCmem(msg)
	defer freeCmem(msgMem)

	var sidOut, sigOut C.cmem_t
	rc := C.cbmpc_ecdsa2p_sign((*C.cbmpc_job2p)(cj), sidMem, key, msgMem, &sidOut, &sigOut)
	if rc != 0 {
		return nil, nil, formatNativeErr("ecdsa2p_sign", rc)
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

	// Copy session ID and messages into C-allocated memory to avoid aliasing Go memory during CGO call
	sidMem := allocCmem(sidIn)
	defer freeCmem(sidMem)
	msgsMem := goBytesSliceToCmems(msgs)
	defer freeCmems(msgsMem)

	var sidOut C.cmem_t
	var sigsOut C.cmems_t
	rc := C.cbmpc_ecdsa2p_sign_batch((*C.cbmpc_job2p)(cj), sidMem, key, msgsMem, &sidOut, &sigsOut)
	if rc != 0 {
		return nil, nil, formatNativeErr("ecdsa2p_sign_batch", rc)
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

	// Copy inputs into C-allocated memory to avoid aliasing Go memory during CGO call
	sidMem := allocCmem(sidIn)
	defer freeCmem(sidMem)
	msgMem := allocCmem(msg)
	defer freeCmem(msgMem)

	var sidOut, sigOut C.cmem_t
	rc := C.cbmpc_ecdsa2p_sign_with_global_abort((*C.cbmpc_job2p)(cj), sidMem, key, msgMem, &sidOut, &sigOut)
	if rc != 0 {
		if C.uint(rc) == C.uint(E_ECDSA_2P_BIT_LEAK) {
			return nil, nil, ErrBitLeak
		}
		return nil, nil, formatNativeErr("ecdsa2p_sign_with_global_abort", rc)
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

	// Copy session ID and messages into C-allocated memory to avoid aliasing Go memory during CGO call
	sidMem := allocCmem(sidIn)
	defer freeCmem(sidMem)
	msgsMem := goBytesSliceToCmems(msgs)
	defer freeCmems(msgsMem)

	var sidOut C.cmem_t
	var sigsOut C.cmems_t
	rc := C.cbmpc_ecdsa2p_sign_with_global_abort_batch((*C.cbmpc_job2p)(cj), sidMem, key, msgsMem, &sidOut, &sigsOut)
	if rc != 0 {
		if C.uint(rc) == C.uint(E_ECDSA_2P_BIT_LEAK) {
			return nil, nil, ErrBitLeak
		}
		return nil, nil, formatNativeErr("ecdsa2p_sign_with_global_abort_batch", rc)
	}

	return cmemToGoBytes(sidOut), cmemsToGoByteSlices(sigsOut), nil
}

// =====================
// PVE (Publicly Verifiable Encryption) wrappers
// =====================

// PVEEncrypt is a C binding wrapper for PVE encrypt.
// The provided KEM is bound to thread-local storage for the duration of the call.
func PVEEncrypt(k KEM, ekBytes, label []byte, curveNID int, xBytes []byte) ([]byte, error) {
	if len(ekBytes) == 0 {
		return nil, errors.New("empty ek bytes")
	}
	if len(label) == 0 {
		return nil, errors.New("empty label")
	}
	if len(xBytes) == 0 {
		return nil, errors.New("empty x bytes")
	}

	// Bind the per-call KEM via TLS on the current OS thread
	if k == nil {
		return nil, errors.New("no KEM provided")
	}
	h := RegisterHandle(k)
	runtime.LockOSThread()
	C.cbmpc_set_kem_tls(h)
	defer func() {
		C.cbmpc_clear_kem_tls()
		FreeHandle(h)
		runtime.UnlockOSThread()
	}()

	ekMem := goBytesToCmem(ekBytes)
	labelMem := goBytesToCmem(label)
	xMem := goBytesToCmem(xBytes)

	var out C.cmem_t
	rc := C.cbmpc_pve_encrypt(ekMem, labelMem, C.int(curveNID), xMem, &out)
	if rc != 0 {
		return nil, formatNativeErr("pve_encrypt", rc)
	}

	return cmemToGoBytes(out), nil
}

// PVEDecrypt is a C binding wrapper for PVE decrypt.
// The provided KEM is bound to thread-local storage for the duration of the call.
func PVEDecrypt(k KEM, dkHandle unsafe.Pointer, ekBytes, pveCT, label []byte, curveNID int) ([]byte, error) {
	if dkHandle == nil {
		return nil, errors.New("nil dk handle")
	}
	if len(ekBytes) == 0 {
		return nil, errors.New("empty ek bytes")
	}
	if len(pveCT) == 0 {
		return nil, errors.New("empty pve ciphertext")
	}
	if len(label) == 0 {
		return nil, errors.New("empty label")
	}

	// Bind the per-call KEM via TLS on the current OS thread
	if k == nil {
		return nil, errors.New("no KEM provided")
	}
	h := RegisterHandle(k)
	runtime.LockOSThread()
	C.cbmpc_set_kem_tls(h)
	defer func() {
		C.cbmpc_clear_kem_tls()
		FreeHandle(h)
		runtime.UnlockOSThread()
	}()

	ekMem := goBytesToCmem(ekBytes)
	pveCTMem := goBytesToCmem(pveCT)
	labelMem := goBytesToCmem(label)

	var out C.cmem_t
	// The dkHandle is an opaque identifier (not a Go pointer) that will be passed through
	// C++ back to Go callbacks. C++ only stores and passes it, never dereferences it.
	// The actual handle lookup happens in the Go KEM implementation.
	rc := C.cbmpc_pve_decrypt(dkHandle, ekMem, pveCTMem, labelMem, C.int(curveNID), &out)
	if rc != 0 {
		return nil, formatNativeErr("pve_decrypt", rc)
	}

	return cmemToGoBytes(out), nil
}

// PVEGetLabel is a C binding wrapper to extract label from PVE ciphertext.
func PVEGetLabel(pveCT []byte) ([]byte, error) {
	if len(pveCT) == 0 {
		return nil, errors.New("empty pve ciphertext")
	}

	pveCTMem := goBytesToCmem(pveCT)

	var out C.cmem_t
	rc := C.cbmpc_pve_get_label(pveCTMem, &out)
	if rc != 0 {
		return nil, formatNativeErr("pve_get_label", rc)
	}

	return cmemToGoBytes(out), nil
}

// PVEGetQPoint extracts the public key Q from a PVE ciphertext as an ecc_point_t.
// Returns an ECCPoint that must be freed with ECCPointFree.
func PVEGetQPoint(pveCT []byte) (ECCPoint, error) {
	if len(pveCT) == 0 {
		return nil, errors.New("empty pve ciphertext")
	}

	pveCTMem := goBytesToCmem(pveCT)

	var point ECCPoint
	rc := C.cbmpc_pve_get_Q_point(pveCTMem, &point)
	if rc != 0 {
		return nil, formatNativeErr("pve_get_Q_point", rc)
	}

	return point, nil
}

// PVEVerifyWithPoint verifies a PVE ciphertext using an ecc_point_t directly.
// This is more efficient than PVEVerify as it avoids serialization/deserialization.
// The provided KEM is bound to thread-local storage for the duration of the call.
//
//nolint:gocritic // QPoint follows Go convention for acronym capitalization
func PVEVerifyWithPoint(k KEM, ekBytes, pveCT []byte, QPoint ECCPoint, label []byte) error {
	if len(ekBytes) == 0 {
		return errors.New("empty ek bytes")
	}
	if len(pveCT) == 0 {
		return errors.New("empty pve ciphertext")
	}
	if QPoint == nil {
		return errors.New("nil Q point")
	}
	if len(label) == 0 {
		return errors.New("empty label")
	}

	// Bind the per-call KEM via TLS on the current OS thread
	if k == nil {
		return errors.New("no KEM provided")
	}
	h := RegisterHandle(k)
	runtime.LockOSThread()
	C.cbmpc_set_kem_tls(h)
	defer func() {
		C.cbmpc_clear_kem_tls()
		FreeHandle(h)
		runtime.UnlockOSThread()
	}()

	ekMem := goBytesToCmem(ekBytes)
	pveCTMem := goBytesToCmem(pveCT)
	labelMem := goBytesToCmem(label)

	rc := C.cbmpc_pve_verify_with_point(ekMem, pveCTMem, QPoint, labelMem)
	if rc != 0 {
		return formatNativeErr("pve_verify_with_point", rc)
	}

	return nil
}

// =====================
// KEM callbacks and registry for FFI policy
// =====================

// KEM is a type alias for kem.KEM.
// This allows the backend to use the public KEM interface without importing it everywhere.
type KEM = kem.KEM

//export go_ffi_kem_encap
func go_ffi_kem_encap(ek_bytes C.cmem_t, rho C.cmem_t, kem_ct_out *C.cmem_t, kem_ss_out *C.cmem_t) C.int {
	if kem_ct_out == nil || kem_ss_out == nil {
		return C.int(C.CBMPC_E_BADARG)
	}

	// Retrieve KEM from thread-local handle set by the caller
	tlsHandle := C.cbmpc_get_kem_tls()
	if tlsHandle == nil {
		return C.int(C.CBMPC_E_NOT_FOUND)
	}
	v, ok := lookupHandle(tlsHandle)
	if !ok {
		return C.int(C.CBMPC_E_NOT_FOUND)
	}
	kem, ok := v.(KEM)
	if !ok || kem == nil {
		return C.int(C.CBMPC_E_NOT_FOUND)
	}

	// Convert inputs to Go
	ek := C.GoBytes(unsafe.Pointer(ek_bytes.data), ek_bytes.size)
	rhoBytes := C.GoBytes(unsafe.Pointer(rho.data), rho.size)
	if len(rhoBytes) != 32 {
		return C.int(C.CBMPC_E_BADARG)
	}

	var rho32 [32]byte
	copy(rho32[:], rhoBytes)

	// Call Go KEM
	ct, ss, err := kem.Encapsulate(ek, rho32)
	if err != nil {
		return C.int(C.CBMPC_E_CRYPTO)
	}

	// Allocate and copy outputs
	ct_cmem := allocCmem(ct)
	ss_cmem := allocCmem(ss)

	*kem_ct_out = ct_cmem
	*kem_ss_out = ss_cmem

	return C.int(C.CBMPC_SUCCESS)
}

//export go_ffi_kem_decap
func go_ffi_kem_decap(dk_handle unsafe.Pointer, kem_ct C.cmem_t, kem_ss_out *C.cmem_t) C.int {
	if dk_handle == nil || kem_ss_out == nil {
		return C.int(C.CBMPC_E_BADARG)
	}

	// Retrieve KEM from thread-local handle set by the caller
	tlsHandle := C.cbmpc_get_kem_tls()
	if tlsHandle == nil {
		return C.int(C.CBMPC_E_NOT_FOUND)
	}
	v, ok := lookupHandle(tlsHandle)
	if !ok {
		return C.int(C.CBMPC_E_NOT_FOUND)
	}
	kem, ok := v.(KEM)
	if !ok || kem == nil {
		return C.int(C.CBMPC_E_NOT_FOUND)
	}

	// Look up the actual Go object from the handle registry
	skHandle, exists := lookupHandle(dk_handle)
	if !exists {
		return C.int(C.CBMPC_E_NOT_FOUND)
	}

	// Convert ciphertext to Go
	ct := C.GoBytes(unsafe.Pointer(kem_ct.data), kem_ct.size)

	// Call Go KEM with the actual Go object
	ss, err := kem.Decapsulate(skHandle, ct)
	if err != nil {
		return C.int(C.CBMPC_E_CRYPTO)
	}

	// Allocate and copy output
	ss_cmem := allocCmem(ss)
	*kem_ss_out = ss_cmem

	return C.int(C.CBMPC_SUCCESS)
}

//export go_ffi_kem_dk_to_ek
func go_ffi_kem_dk_to_ek(dk_handle unsafe.Pointer, ek_bytes_out *C.cmem_t) C.int {
	if dk_handle == nil || ek_bytes_out == nil {
		return C.int(C.CBMPC_E_BADARG)
	}

	// Retrieve KEM from thread-local handle set by the caller
	tlsHandle := C.cbmpc_get_kem_tls()
	if tlsHandle == nil {
		return C.int(C.CBMPC_E_NOT_FOUND)
	}
	v, ok := lookupHandle(tlsHandle)
	if !ok {
		return C.int(C.CBMPC_E_NOT_FOUND)
	}
	_, ok = v.(KEM)
	if !ok {
		return C.int(C.CBMPC_E_NOT_FOUND)
	}

	// Not implemented by design: callers must provide EK explicitly.
	return C.int(C.CBMPC_E_NOT_SUPPORTED)
}

// =====================
// ZK Proof Operations - UC_DL
// =====================

// UCDLProve creates a UC_DL proof for proving knowledge of w such that Q = w*G.
// Returns the serialized proof as bytes.
func UCDLProve(qPoint ECCPoint, w, sessionID []byte, aux uint64) ([]byte, error) {
	if qPoint == nil {
		return nil, errors.New("nil Q point")
	}
	if len(w) == 0 {
		return nil, errors.New("empty witness")
	}
	if len(sessionID) == 0 {
		return nil, errors.New("empty session ID")
	}

	wMem := goBytesToCmem(w)
	sessionIDMem := goBytesToCmem(sessionID)

	var out C.cmem_t
	rc := C.cbmpc_uc_dl_prove(qPoint, wMem, sessionIDMem, C.uint64_t(aux), &out)
	if rc != 0 {
		return nil, formatNativeErr("uc_dl_prove", rc)
	}

	return cmemToGoBytes(out), nil
}

// UCDLVerify verifies a UC_DL proof.
// The proof parameter should be serialized proof bytes.
func UCDLVerify(proof []byte, qPoint ECCPoint, sessionID []byte, aux uint64) error {
	if len(proof) == 0 {
		return errors.New("empty proof")
	}
	if qPoint == nil {
		return errors.New("nil Q point")
	}
	if len(sessionID) == 0 {
		return errors.New("empty session ID")
	}

	proofMem := goBytesToCmem(proof)
	sessionIDMem := goBytesToCmem(sessionID)

	rc := C.cbmpc_uc_dl_verify(proofMem, qPoint, sessionIDMem, C.uint64_t(aux))
	if rc != 0 {
		return formatNativeErr("uc_dl_verify", rc)
	}

	return nil
}
