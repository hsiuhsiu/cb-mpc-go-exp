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

// PVEBatchEncrypt is a C binding wrapper for batch PVE encrypt.
// The provided KEM is bound to thread-local storage for the duration of the call.
func PVEBatchEncrypt(k KEM, ekBytes, label []byte, curveNID int, xScalarsBytes [][]byte) ([]byte, error) {
	if len(ekBytes) == 0 {
		return nil, errors.New("empty ek bytes")
	}
	if len(label) == 0 {
		return nil, errors.New("empty label")
	}
	if len(xScalarsBytes) == 0 {
		return nil, errors.New("empty x scalars")
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
	xScalarsMem := goBytesSliceToCmems(xScalarsBytes)
	defer freeCmems(xScalarsMem)

	var out C.cmem_t
	rc := C.cbmpc_pve_batch_encrypt(ekMem, labelMem, C.int(curveNID), xScalarsMem, &out)
	if rc != 0 {
		return nil, formatNativeErr("pve_batch_encrypt", rc)
	}

	return cmemToGoBytes(out), nil
}

// PVEBatchVerify is a C binding wrapper for batch PVE verify.
// The provided KEM is bound to thread-local storage for the duration of the call.
func PVEBatchVerify(k KEM, ekBytes, pveCT []byte, qPoints []ECCPoint, label []byte) error {
	if len(ekBytes) == 0 {
		return errors.New("empty ek bytes")
	}
	if len(pveCT) == 0 {
		return errors.New("empty pve ciphertext")
	}
	if len(qPoints) == 0 {
		return errors.New("empty Q points")
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

	// Convert []ECCPoint to C array
	cPoints := make([]C.cbmpc_ecc_point, len(qPoints))
	for i, p := range qPoints {
		if p == nil {
			return errors.New("nil point in Q points array")
		}
		cPoints[i] = p
	}

	ekMem := goBytesToCmem(ekBytes)
	pveCTMem := goBytesToCmem(pveCT)
	labelMem := goBytesToCmem(label)

	rc := C.cbmpc_pve_batch_verify(ekMem, pveCTMem, &cPoints[0], C.int(len(cPoints)), labelMem)
	if rc != 0 {
		return formatNativeErr("pve_batch_verify", rc)
	}

	return nil
}

// PVEBatchDecrypt is a C binding wrapper for batch PVE decrypt.
// The provided KEM is bound to thread-local storage for the duration of the call.
func PVEBatchDecrypt(k KEM, dkHandle unsafe.Pointer, ekBytes, pveCT, label []byte, curveNID int) ([][]byte, error) {
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

	var out C.cmems_t
	rc := C.cbmpc_pve_batch_decrypt(dkHandle, ekMem, pveCTMem, labelMem, C.int(curveNID), &out)
	if rc != 0 {
		return nil, formatNativeErr("pve_batch_decrypt", rc)
	}

	return cmemsToGoByteSlices(out), nil
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

// =====================
// ZK Proof Operations - UC_Batch_DL
// =====================

// UCBatchDLProve creates a UC_Batch_DL proof for proving knowledge of multiple w's such that Q[i] = w[i]*G.
// Returns the serialized proof as bytes.
func UCBatchDLProve(qPoints []ECCPoint, wScalarsBytes [][]byte, sessionID []byte, aux uint64) ([]byte, error) {
	if len(qPoints) == 0 {
		return nil, errors.New("empty Q points")
	}
	if len(wScalarsBytes) == 0 {
		return nil, errors.New("empty w scalars")
	}
	if len(qPoints) != len(wScalarsBytes) {
		return nil, errors.New("Q points and w scalars count mismatch")
	}
	if len(sessionID) == 0 {
		return nil, errors.New("empty session ID")
	}

	// Convert []ECCPoint to C array
	cPoints := make([]C.cbmpc_ecc_point, len(qPoints))
	for i, p := range qPoints {
		if p == nil {
			return nil, errors.New("nil point in Q points array")
		}
		cPoints[i] = p
	}

	wScalarsMem := goBytesSliceToCmems(wScalarsBytes)
	defer freeCmems(wScalarsMem)
	sessionIDMem := goBytesToCmem(sessionID)

	var out C.cmem_t
	rc := C.cbmpc_uc_batch_dl_prove(&cPoints[0], C.int(len(cPoints)), wScalarsMem, sessionIDMem, C.uint64_t(aux), &out)
	if rc != 0 {
		return nil, formatNativeErr("uc_batch_dl_prove", rc)
	}

	return cmemToGoBytes(out), nil
}

// UCBatchDLVerify verifies a UC_Batch_DL proof.
// The proof parameter should be serialized proof bytes.
func UCBatchDLVerify(proof []byte, qPoints []ECCPoint, sessionID []byte, aux uint64) error {
	if len(proof) == 0 {
		return errors.New("empty proof")
	}
	if len(qPoints) == 0 {
		return errors.New("empty Q points")
	}
	if len(sessionID) == 0 {
		return errors.New("empty session ID")
	}

	// Convert []ECCPoint to C array
	cPoints := make([]C.cbmpc_ecc_point, len(qPoints))
	for i, p := range qPoints {
		if p == nil {
			return errors.New("nil point in Q points array")
		}
		cPoints[i] = p
	}

	proofMem := goBytesToCmem(proof)
	sessionIDMem := goBytesToCmem(sessionID)

	rc := C.cbmpc_uc_batch_dl_verify(proofMem, &cPoints[0], C.int(len(cPoints)), sessionIDMem, C.uint64_t(aux))
	if rc != 0 {
		return formatNativeErr("uc_batch_dl_verify", rc)
	}

	return nil
}

// =====================
// ZK Proof Operations - DH
// =====================

// DHProve creates a DH proof for proving B = w*Q where A = w*G.
// Returns the serialized proof as bytes.
func DHProve(qPoint, aPoint, bPoint ECCPoint, w, sessionID []byte, aux uint64) ([]byte, error) {
	if qPoint == nil {
		return nil, errors.New("nil Q point")
	}
	if aPoint == nil {
		return nil, errors.New("nil A point")
	}
	if bPoint == nil {
		return nil, errors.New("nil B point")
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
	rc := C.cbmpc_dh_prove(qPoint, aPoint, bPoint, wMem, sessionIDMem, C.uint64_t(aux), &out)
	if rc != 0 {
		return nil, formatNativeErr("dh_prove", rc)
	}

	return cmemToGoBytes(out), nil
}

// DHVerify verifies a DH proof.
// The proof parameter should be serialized proof bytes.
func DHVerify(proof []byte, qPoint, aPoint, bPoint ECCPoint, sessionID []byte, aux uint64) error {
	if len(proof) == 0 {
		return errors.New("empty proof")
	}
	if qPoint == nil {
		return errors.New("nil Q point")
	}
	if aPoint == nil {
		return errors.New("nil A point")
	}
	if bPoint == nil {
		return errors.New("nil B point")
	}
	if len(sessionID) == 0 {
		return errors.New("empty session ID")
	}

	proofMem := goBytesToCmem(proof)
	sessionIDMem := goBytesToCmem(sessionID)

	rc := C.cbmpc_dh_verify(proofMem, qPoint, aPoint, bPoint, sessionIDMem, C.uint64_t(aux))
	if rc != 0 {
		return formatNativeErr("dh_verify", rc)
	}

	return nil
}

// =====================
// ZK Proof Operations - UC_ElGamalCom
// =====================

// UCElGamalComProve creates a UC_ElGamalCom proof for proving knowledge of x and r such that UV = (x*G, r*G + x*Q).
// Returns the serialized proof as bytes.
func UCElGamalComProve(qPoint ECCPoint, uvCommitment ECElGamalCommitment, x, r, sessionID []byte, aux uint64) ([]byte, error) {
	if qPoint == nil {
		return nil, errors.New("nil Q point")
	}
	if uvCommitment == nil {
		return nil, errors.New("nil UV commitment")
	}
	if len(x) == 0 {
		return nil, errors.New("empty x witness")
	}
	if len(r) == 0 {
		return nil, errors.New("empty r witness")
	}
	if len(sessionID) == 0 {
		return nil, errors.New("empty session ID")
	}

	xMem := goBytesToCmem(x)
	rMem := goBytesToCmem(r)
	sessionIDMem := goBytesToCmem(sessionID)

	var out C.cmem_t
	rc := C.cbmpc_uc_elgamal_com_prove(qPoint, uvCommitment, xMem, rMem, sessionIDMem, C.uint64_t(aux), &out)
	if rc != 0 {
		return nil, formatNativeErr("uc_elgamal_com_prove", rc)
	}

	return cmemToGoBytes(out), nil
}

// UCElGamalComVerify verifies a UC_ElGamalCom proof.
// The proof parameter should be serialized proof bytes.
func UCElGamalComVerify(proof []byte, qPoint ECCPoint, uvCommitment ECElGamalCommitment, sessionID []byte, aux uint64) error {
	if len(proof) == 0 {
		return errors.New("empty proof")
	}
	if qPoint == nil {
		return errors.New("nil Q point")
	}
	if uvCommitment == nil {
		return errors.New("nil UV commitment")
	}
	if len(sessionID) == 0 {
		return errors.New("empty session ID")
	}

	proofMem := goBytesToCmem(proof)
	sessionIDMem := goBytesToCmem(sessionID)

	rc := C.cbmpc_uc_elgamal_com_verify(proofMem, qPoint, uvCommitment, sessionIDMem, C.uint64_t(aux))
	if rc != 0 {
		return formatNativeErr("uc_elgamal_com_verify", rc)
	}

	return nil
}

// =====================
// ZK Proof Operations - ElGamalCom_PubShare_Equ
// =====================

// ElGamalComPubShareEquProve creates an ElGamalCom_PubShare_Equ proof.
// Returns the serialized proof as bytes.
func ElGamalComPubShareEquProve(qPoint, aPoint ECCPoint, bCommitment ECElGamalCommitment, r, sessionID []byte, aux uint64) ([]byte, error) {
	if qPoint == nil {
		return nil, errors.New("nil Q point")
	}
	if aPoint == nil {
		return nil, errors.New("nil A point")
	}
	if bCommitment == nil {
		return nil, errors.New("nil B commitment")
	}
	if len(r) == 0 {
		return nil, errors.New("empty r witness")
	}
	if len(sessionID) == 0 {
		return nil, errors.New("empty session ID")
	}

	rMem := goBytesToCmem(r)
	sessionIDMem := goBytesToCmem(sessionID)

	var out C.cmem_t
	rc := C.cbmpc_elgamal_com_pub_share_equ_prove(qPoint, aPoint, bCommitment, rMem, sessionIDMem, C.uint64_t(aux), &out)
	if rc != 0 {
		return nil, formatNativeErr("elgamal_com_pub_share_equ_prove", rc)
	}

	return cmemToGoBytes(out), nil
}

// ElGamalComPubShareEquVerify verifies an ElGamalCom_PubShare_Equ proof.
// The proof parameter should be serialized proof bytes.
func ElGamalComPubShareEquVerify(proof []byte, qPoint, aPoint ECCPoint, bCommitment ECElGamalCommitment, sessionID []byte, aux uint64) error {
	if len(proof) == 0 {
		return errors.New("empty proof")
	}
	if qPoint == nil {
		return errors.New("nil Q point")
	}
	if aPoint == nil {
		return errors.New("nil A point")
	}
	if bCommitment == nil {
		return errors.New("nil B commitment")
	}
	if len(sessionID) == 0 {
		return errors.New("empty session ID")
	}

	proofMem := goBytesToCmem(proof)
	sessionIDMem := goBytesToCmem(sessionID)

	rc := C.cbmpc_elgamal_com_pub_share_equ_verify(proofMem, qPoint, aPoint, bCommitment, sessionIDMem, C.uint64_t(aux))
	if rc != 0 {
		return formatNativeErr("elgamal_com_pub_share_equ_verify", rc)
	}

	return nil
}

// =====================
// ZK Proof Operations - ElGamalCom_Mult
// =====================

// ElGamalComMultProve creates an ElGamalCom_Mult proof.
// Returns the serialized proof as bytes.
func ElGamalComMultProve(qPoint ECCPoint, aCommitment, bCommitment, cCommitment ECElGamalCommitment, rB, rC, b, sessionID []byte, aux uint64) ([]byte, error) {
	if qPoint == nil {
		return nil, errors.New("nil Q point")
	}
	if aCommitment == nil {
		return nil, errors.New("nil A commitment")
	}
	if bCommitment == nil {
		return nil, errors.New("nil B commitment")
	}
	if cCommitment == nil {
		return nil, errors.New("nil C commitment")
	}
	if len(rB) == 0 {
		return nil, errors.New("empty rB witness")
	}
	if len(rC) == 0 {
		return nil, errors.New("empty rC witness")
	}
	if len(b) == 0 {
		return nil, errors.New("empty b witness")
	}
	if len(sessionID) == 0 {
		return nil, errors.New("empty session ID")
	}

	rBMem := goBytesToCmem(rB)
	rCMem := goBytesToCmem(rC)
	bMem := goBytesToCmem(b)
	sessionIDMem := goBytesToCmem(sessionID)

	var out C.cmem_t
	rc := C.cbmpc_elgamal_com_mult_prove(qPoint, aCommitment, bCommitment, cCommitment, rBMem, rCMem, bMem, sessionIDMem, C.uint64_t(aux), &out)
	if rc != 0 {
		return nil, formatNativeErr("elgamal_com_mult_prove", rc)
	}

	return cmemToGoBytes(out), nil
}

// ElGamalComMultVerify verifies an ElGamalCom_Mult proof.
// The proof parameter should be serialized proof bytes.
func ElGamalComMultVerify(proof []byte, qPoint ECCPoint, aCommitment, bCommitment, cCommitment ECElGamalCommitment, sessionID []byte, aux uint64) error {
	if len(proof) == 0 {
		return errors.New("empty proof")
	}
	if qPoint == nil {
		return errors.New("nil Q point")
	}
	if aCommitment == nil {
		return errors.New("nil A commitment")
	}
	if bCommitment == nil {
		return errors.New("nil B commitment")
	}
	if cCommitment == nil {
		return errors.New("nil C commitment")
	}
	if len(sessionID) == 0 {
		return errors.New("empty session ID")
	}

	proofMem := goBytesToCmem(proof)
	sessionIDMem := goBytesToCmem(sessionID)

	rc := C.cbmpc_elgamal_com_mult_verify(proofMem, qPoint, aCommitment, bCommitment, cCommitment, sessionIDMem, C.uint64_t(aux))
	if rc != 0 {
		return formatNativeErr("elgamal_com_mult_verify", rc)
	}

	return nil
}

// =====================
// ZK Proof Operations - UC_ElGamalCom_Mult_Private_Scalar
// =====================

// UCElGamalComMultPrivateScalarProve creates a UC_ElGamalCom_Mult_Private_Scalar proof.
// Returns the serialized proof as bytes.
func UCElGamalComMultPrivateScalarProve(ePoint ECCPoint, eACommitment, eBCommitment ECElGamalCommitment, r0, c, sessionID []byte, aux uint64) ([]byte, error) {
	if ePoint == nil {
		return nil, errors.New("nil E point")
	}
	if eACommitment == nil {
		return nil, errors.New("nil eA commitment")
	}
	if eBCommitment == nil {
		return nil, errors.New("nil eB commitment")
	}
	if len(r0) == 0 {
		return nil, errors.New("empty r0 witness")
	}
	if len(c) == 0 {
		return nil, errors.New("empty c witness")
	}
	if len(sessionID) == 0 {
		return nil, errors.New("empty session ID")
	}

	r0Mem := goBytesToCmem(r0)
	cMem := goBytesToCmem(c)
	sessionIDMem := goBytesToCmem(sessionID)

	var out C.cmem_t
	rc := C.cbmpc_uc_elgamal_com_mult_private_scalar_prove(ePoint, eACommitment, eBCommitment, r0Mem, cMem, sessionIDMem, C.uint64_t(aux), &out)
	if rc != 0 {
		return nil, formatNativeErr("uc_elgamal_com_mult_private_scalar_prove", rc)
	}

	return cmemToGoBytes(out), nil
}

// UCElGamalComMultPrivateScalarVerify verifies a UC_ElGamalCom_Mult_Private_Scalar proof.
// The proof parameter should be serialized proof bytes.
func UCElGamalComMultPrivateScalarVerify(proof []byte, ePoint ECCPoint, eACommitment, eBCommitment ECElGamalCommitment, sessionID []byte, aux uint64) error {
	if len(proof) == 0 {
		return errors.New("empty proof")
	}
	if ePoint == nil {
		return errors.New("nil E point")
	}
	if eACommitment == nil {
		return errors.New("nil eA commitment")
	}
	if eBCommitment == nil {
		return errors.New("nil eB commitment")
	}
	if len(sessionID) == 0 {
		return errors.New("empty session ID")
	}

	proofMem := goBytesToCmem(proof)
	sessionIDMem := goBytesToCmem(sessionID)

	rc := C.cbmpc_uc_elgamal_com_mult_private_scalar_verify(proofMem, ePoint, eACommitment, eBCommitment, sessionIDMem, C.uint64_t(aux))
	if rc != 0 {
		return formatNativeErr("uc_elgamal_com_mult_private_scalar_verify", rc)
	}

	return nil
}

// =====================
// ECDSA MP Protocols
// =====================

// ECDSAMP DKG is a C binding wrapper for multi-party ECDSA distributed key generation.
func ECDSAMP_DKG(cj unsafe.Pointer, curveNID int) (ECDSAMPKey, []byte, error) {
	if cj == nil {
		return nil, nil, errors.New("nil job")
	}

	var key ECDSAMPKey
	var sidOut C.cmem_t
	rc := C.cbmpc_ecdsamp_dkg((*C.cbmpc_jobmp)(cj), C.int(curveNID), &key, &sidOut)
	if rc != 0 {
		return nil, nil, formatNativeErr("ecdsamp_dkg", rc)
	}

	return key, cmemToGoBytes(sidOut), nil
}

// ECDSAMPRefresh is a C binding wrapper for multi-party ECDSA key refresh.
// sidIn can be empty to generate a new session ID.
func ECDSAMPRefresh(cj unsafe.Pointer, key ECDSAMPKey, sidIn []byte) (ECDSAMPKey, []byte, error) {
	if cj == nil {
		return nil, nil, errors.New("nil job")
	}
	if key == nil {
		return nil, nil, errors.New("nil key")
	}

	// Copy session ID into C-allocated memory to avoid aliasing Go memory during CGO call
	sidMem := allocCmem(sidIn)
	defer freeCmem(sidMem)

	var newKey ECDSAMPKey
	var sidOut C.cmem_t
	rc := C.cbmpc_ecdsamp_refresh((*C.cbmpc_jobmp)(cj), sidMem, key, &sidOut, &newKey)
	if rc != 0 {
		return nil, nil, formatNativeErr("ecdsamp_refresh", rc)
	}
	return newKey, cmemToGoBytes(sidOut), nil
}

// ECDSAMPSign is a C binding wrapper for multi-party ECDSA signing.
func ECDSAMPSign(cj unsafe.Pointer, key ECDSAMPKey, msg []byte, sigReceiver int) ([]byte, error) {
	if cj == nil {
		return nil, errors.New("nil job")
	}
	if key == nil {
		return nil, errors.New("nil key")
	}
	if len(msg) == 0 {
		return nil, errors.New("empty message")
	}

	// Copy message into C-allocated memory for the signing operation
	msgMem := allocCmem(msg)
	defer freeCmem(msgMem)

	var sigOut C.cmem_t
	rc := C.cbmpc_ecdsamp_sign((*C.cbmpc_jobmp)(cj), key, msgMem, C.int(sigReceiver), &sigOut)
	if rc != 0 {
		return nil, formatNativeErr("ecdsamp_sign", rc)
	}

	return cmemToGoBytes(sigOut), nil
}

// =====================
// Schnorr 2P Protocols
// =====================

// Schnorr2PKey is an opaque handle to a C++ schnorr2p key (eckey::key_share_2p_t).
type Schnorr2PKey = *C.cbmpc_schnorr2p_key

// Schnorr2PDKG is a C binding wrapper for 2-party Schnorr distributed key generation.
func Schnorr2PDKG(cj unsafe.Pointer, curveNID int) (Schnorr2PKey, error) {
	if cj == nil {
		return nil, errors.New("nil job")
	}

	var key Schnorr2PKey
	rc := C.cbmpc_schnorr2p_dkg((*C.cbmpc_job2p)(cj), C.int(curveNID), &key)
	if rc != 0 {
		return nil, formatNativeErr("schnorr2p_dkg", rc)
	}
	return key, nil
}

// Schnorr2PKeyFree frees a Schnorr 2P key.
func Schnorr2PKeyFree(key Schnorr2PKey) {
	if key != nil {
		C.cbmpc_schnorr2p_key_free(key)
	}
}

// Schnorr2PKeySerialize serializes a Schnorr 2P key to bytes.
func Schnorr2PKeySerialize(key Schnorr2PKey) ([]byte, error) {
	if key == nil {
		return nil, errors.New("nil key")
	}

	var out C.cmem_t
	rc := C.cbmpc_schnorr2p_key_serialize(key, &out)
	if rc != 0 {
		return nil, formatNativeErr("schnorr2p_key_serialize", rc)
	}

	return cmemToGoBytes(out), nil
}

// Schnorr2PKeyDeserialize deserializes bytes into a Schnorr 2P key.
func Schnorr2PKeyDeserialize(serialized []byte) (Schnorr2PKey, error) {
	if len(serialized) == 0 {
		return nil, errors.New("empty serialized key")
	}

	serializedMem := goBytesToCmem(serialized)

	var key Schnorr2PKey
	rc := C.cbmpc_schnorr2p_key_deserialize(serializedMem, &key)
	if rc != 0 {
		return nil, formatNativeErr("schnorr2p_key_deserialize", rc)
	}

	return key, nil
}

// Schnorr2PKeyGetPublicKey gets the public key from a Schnorr 2P key (compressed format).
func Schnorr2PKeyGetPublicKey(key Schnorr2PKey) ([]byte, error) {
	if key == nil {
		return nil, errors.New("nil key")
	}

	var out C.cmem_t
	rc := C.cbmpc_schnorr2p_key_get_public_key(key, &out)
	if rc != 0 {
		return nil, formatNativeErr("schnorr2p_key_get_public_key", rc)
	}

	return cmemToGoBytes(out), nil
}

// Schnorr2PKeyGetCurve gets the curve NID from a Schnorr 2P key.
func Schnorr2PKeyGetCurve(key Schnorr2PKey) (int, error) {
	if key == nil {
		return 0, errors.New("nil key")
	}

	var curveNID C.int
	rc := C.cbmpc_schnorr2p_key_get_curve(key, &curveNID)
	if rc != 0 {
		return 0, formatNativeErr("schnorr2p_key_get_curve", rc)
	}

	return int(curveNID), nil
}

// SchnorrVariant represents Schnorr signature variant (EdDSA or BIP340).
type SchnorrVariant int

const (
	// SchnorrVariantEdDSA represents EdDSA (Ed25519) variant.
	SchnorrVariantEdDSA SchnorrVariant = C.CBMPC_SCHNORR_VARIANT_EDDSA
	// SchnorrVariantBIP340 represents BIP340 (secp256k1) variant.
	SchnorrVariantBIP340 SchnorrVariant = C.CBMPC_SCHNORR_VARIANT_BIP340
)

// Schnorr2PSign is a C binding wrapper for 2-party Schnorr signing.
func Schnorr2PSign(cj unsafe.Pointer, key Schnorr2PKey, msg []byte, variant SchnorrVariant) ([]byte, error) {
	if cj == nil {
		return nil, errors.New("nil job")
	}
	if key == nil {
		return nil, errors.New("nil key")
	}
	if len(msg) == 0 {
		return nil, errors.New("empty message")
	}

	// Copy message into C-allocated memory to avoid aliasing Go memory during CGO call
	msgMem := allocCmem(msg)
	defer freeCmem(msgMem)

	var sigOut C.cmem_t
	rc := C.cbmpc_schnorr2p_sign((*C.cbmpc_job2p)(cj), key, msgMem, C.int(variant), &sigOut)
	if rc != 0 {
		return nil, formatNativeErr("schnorr2p_sign", rc)
	}

	return cmemToGoBytes(sigOut), nil
}

// Schnorr2PSignBatch signs multiple messages with a Schnorr 2P key (batch mode).
func Schnorr2PSignBatch(cj unsafe.Pointer, key Schnorr2PKey, msgs [][]byte, variant SchnorrVariant) ([][]byte, error) {
	if cj == nil {
		return nil, errors.New("nil job")
	}
	if key == nil {
		return nil, errors.New("nil key")
	}
	if len(msgs) == 0 {
		return nil, errors.New("empty messages")
	}

	// Copy messages into C-allocated memory to avoid aliasing Go memory during CGO call
	msgsMem := goBytesSliceToCmems(msgs)
	defer freeCmems(msgsMem)

	var sigsOut C.cmems_t
	rc := C.cbmpc_schnorr2p_sign_batch((*C.cbmpc_job2p)(cj), key, msgsMem, C.int(variant), &sigsOut)
	if rc != 0 {
		return nil, formatNativeErr("schnorr2p_sign_batch", rc)
	}

	return cmemsToGoByteSlices(sigsOut), nil
}

// =====================
// Schnorr MP Protocols
// =====================

// SchnorrMPSign is a C binding wrapper for multi-party Schnorr signing.
// Only the party with party_idx == sig_receiver will receive the final signature.
func SchnorrMPSign(cj unsafe.Pointer, key ECDSAMPKey, msg []byte, sigReceiver int, variant SchnorrVariant) ([]byte, error) {
	if cj == nil {
		return nil, errors.New("nil job")
	}
	if key == nil {
		return nil, errors.New("nil key")
	}
	if len(msg) == 0 {
		return nil, errors.New("empty message")
	}

	// Copy message into C-allocated memory for the signing operation
	msgMem := allocCmem(msg)
	defer freeCmem(msgMem)

	var sigOut C.cmem_t
	rc := C.cbmpc_schnorrmp_sign((*C.cbmpc_jobmp)(cj), key, msgMem, C.int(sigReceiver), C.int(variant), &sigOut)
	if rc != 0 {
		return nil, formatNativeErr("schnorrmp_sign", rc)
	}

	return cmemToGoBytes(sigOut), nil
}

// SchnorrMPSignBatch signs multiple messages with a Schnorr MP key (batch mode).
// Only the party with party_idx == sig_receiver will receive the final signatures.
func SchnorrMPSignBatch(cj unsafe.Pointer, key ECDSAMPKey, msgs [][]byte, sigReceiver int, variant SchnorrVariant) ([][]byte, error) {
	if cj == nil {
		return nil, errors.New("nil job")
	}
	if key == nil {
		return nil, errors.New("nil key")
	}
	if len(msgs) == 0 {
		return nil, errors.New("empty messages")
	}

	// Copy messages into C-allocated memory to avoid aliasing Go memory during CGO call
	msgsMem := goBytesSliceToCmems(msgs)
	defer freeCmems(msgsMem)

	var sigsOut C.cmems_t
	rc := C.cbmpc_schnorrmp_sign_batch((*C.cbmpc_jobmp)(cj), key, msgsMem, C.int(sigReceiver), C.int(variant), &sigsOut)
	if rc != 0 {
		return nil, formatNativeErr("schnorrmp_sign_batch", rc)
	}

	return cmemsToGoByteSlices(sigsOut), nil
}

// ============================================================
// Curve Operations
// ============================================================

// CurveRandomScalar generates a random scalar for the given curve.
// Returns scalar bytes in big-endian format.
func CurveRandomScalar(curveNID int) ([]byte, error) {
	var scalarOut C.cmem_t
	rc := C.cbmpc_curve_random_scalar(C.int(curveNID), &scalarOut)
	if rc != 0 {
		return nil, formatNativeErr("curve_random_scalar", rc)
	}
	return cmemToGoBytes(scalarOut), nil
}

// CurveGetGenerator returns the generator point for the given curve.
// The returned ECCPoint must be freed by the caller.
func CurveGetGenerator(curveNID int) (ECCPoint, error) {
	var generatorOut C.cbmpc_ecc_point
	rc := C.cbmpc_curve_get_generator(C.int(curveNID), &generatorOut)
	if rc != 0 {
		return nil, formatNativeErr("curve_get_generator", rc)
	}
	return ECCPoint(generatorOut), nil
}

// CurveMulGenerator multiplies the generator point by a scalar: result = scalar * G.
// scalarBytes should be in big-endian format.
// The returned ECCPoint must be freed by the caller.
func CurveMulGenerator(curveNID int, scalarBytes []byte) (ECCPoint, error) {
	if len(scalarBytes) == 0 {
		return nil, errors.New("empty scalar")
	}

	scalarMem := goBytesToCmem(scalarBytes)
	var pointOut C.cbmpc_ecc_point
	rc := C.cbmpc_curve_mul_generator(C.int(curveNID), scalarMem, &pointOut)
	if rc != 0 {
		return nil, formatNativeErr("curve_mul_generator", rc)
	}
	return ECCPoint(pointOut), nil
}

// ECCPointMul multiplies a point by a scalar: result = scalar * point.
// scalarBytes should be in big-endian format.
// The returned ECCPoint must be freed by the caller.
func ECCPointMul(point ECCPoint, scalarBytes []byte) (ECCPoint, error) {
	if point == nil {
		return nil, errors.New("nil point")
	}
	if len(scalarBytes) == 0 {
		return nil, errors.New("empty scalar")
	}

	scalarMem := goBytesToCmem(scalarBytes)
	var resultOut C.cbmpc_ecc_point
	rc := C.cbmpc_ecc_point_mul(point, scalarMem, &resultOut)
	if rc != 0 {
		return nil, formatNativeErr("ecc_point_mul", rc)
	}
	return ECCPoint(resultOut), nil
}

// ECCPointAdd adds two ECC points: result = pointA + pointB.
// The returned ECCPoint must be freed by the caller.
func ECCPointAdd(pointA, pointB ECCPoint) (ECCPoint, error) {
	if pointA == nil {
		return nil, errors.New("nil pointA")
	}
	if pointB == nil {
		return nil, errors.New("nil pointB")
	}

	var resultOut C.cbmpc_ecc_point
	rc := C.cbmpc_ecc_point_add(pointA, pointB, &resultOut)
	if rc != 0 {
		return nil, formatNativeErr("ecc_point_add", rc)
	}
	return ECCPoint(resultOut), nil
}

// ScalarAdd adds two scalars modulo curve order: result = (scalarA + scalarB) mod q.
// scalarABytes and scalarBBytes should be in big-endian format.
// Returns result scalar bytes in big-endian format.
func ScalarAdd(scalarABytes, scalarBBytes []byte, curveNID int) ([]byte, error) {
	if len(scalarABytes) == 0 {
		return nil, errors.New("empty scalarA")
	}
	if len(scalarBBytes) == 0 {
		return nil, errors.New("empty scalarB")
	}

	scalarAMem := goBytesToCmem(scalarABytes)
	scalarBMem := goBytesToCmem(scalarBBytes)

	var resultOut C.cmem_t
	rc := C.cbmpc_scalar_add(scalarAMem, scalarBMem, C.int(curveNID), &resultOut)
	if rc != 0 {
		return nil, formatNativeErr("scalar_add", rc)
	}
	return cmemToGoBytes(resultOut), nil
}

// =====================
// ZK Proof Operations - Valid_Paillier
// =====================

// ValidPaillierProve creates a Valid_Paillier proof for proving that a Paillier key is well-formed.
// Returns the serialized proof as bytes.
func ValidPaillierProve(paillier Paillier, sessionID []byte, aux uint64) ([]byte, error) {
	if paillier == nil {
		return nil, errors.New("nil paillier")
	}
	if len(sessionID) == 0 {
		return nil, errors.New("empty session ID")
	}

	sessionIDMem := goBytesToCmem(sessionID)

	var out C.cmem_t
	rc := C.cbmpc_valid_paillier_prove(paillier, sessionIDMem, C.uint64_t(aux), &out)
	if rc != 0 {
		return nil, formatNativeErr("valid_paillier_prove", rc)
	}

	return cmemToGoBytes(out), nil
}

// ValidPaillierVerify verifies a Valid_Paillier proof.
// The proof parameter should be serialized proof bytes.
func ValidPaillierVerify(proof []byte, paillier Paillier, sessionID []byte, aux uint64) error {
	if len(proof) == 0 {
		return errors.New("empty proof")
	}
	if paillier == nil {
		return errors.New("nil paillier")
	}
	if len(sessionID) == 0 {
		return errors.New("empty session ID")
	}

	proofMem := goBytesToCmem(proof)
	sessionIDMem := goBytesToCmem(sessionID)

	rc := C.cbmpc_valid_paillier_verify(proofMem, paillier, sessionIDMem, C.uint64_t(aux))
	if rc != 0 {
		return formatNativeErr("valid_paillier_verify", rc)
	}

	return nil
}

// =====================
// ZK Proof Operations - Paillier_Zero
// =====================

// PaillierZeroProve creates a Paillier_Zero proof for proving that a ciphertext encrypts zero.
// Returns the serialized proof as bytes.
func PaillierZeroProve(paillier Paillier, c, r, sessionID []byte, aux uint64) ([]byte, error) {
	if paillier == nil {
		return nil, errors.New("nil paillier")
	}
	if len(c) == 0 {
		return nil, errors.New("empty ciphertext")
	}
	if len(r) == 0 {
		return nil, errors.New("empty randomness")
	}
	if len(sessionID) == 0 {
		return nil, errors.New("empty session ID")
	}

	cMem := goBytesToCmem(c)
	rMem := goBytesToCmem(r)
	sessionIDMem := goBytesToCmem(sessionID)

	var out C.cmem_t
	rc := C.cbmpc_paillier_zero_prove(paillier, cMem, rMem, sessionIDMem, C.uint64_t(aux), &out)
	if rc != 0 {
		return nil, formatNativeErr("paillier_zero_prove", rc)
	}

	return cmemToGoBytes(out), nil
}

// PaillierZeroVerify verifies a Paillier_Zero proof.
// The proof parameter should be serialized proof bytes.
func PaillierZeroVerify(proof []byte, paillier Paillier, c, sessionID []byte, aux uint64) error {
	if len(proof) == 0 {
		return errors.New("empty proof")
	}
	if paillier == nil {
		return errors.New("nil paillier")
	}
	if len(c) == 0 {
		return errors.New("empty ciphertext")
	}
	if len(sessionID) == 0 {
		return errors.New("empty session ID")
	}

	proofMem := goBytesToCmem(proof)
	cMem := goBytesToCmem(c)
	sessionIDMem := goBytesToCmem(sessionID)

	rc := C.cbmpc_paillier_zero_verify(proofMem, paillier, cMem, sessionIDMem, C.uint64_t(aux))
	if rc != 0 {
		return formatNativeErr("paillier_zero_verify", rc)
	}

	return nil
}

// =====================
// ZK Proof Operations - Two_Paillier_Equal
// =====================

// TwoPaillierEqualProve creates a Two_Paillier_Equal proof for proving that two ciphertexts
// (under different Paillier keys) encrypt the same plaintext.
// Returns the serialized proof as bytes.
func TwoPaillierEqualProve(q []byte, p0 Paillier, c0 []byte, p1 Paillier, c1, x, r0, r1, sessionID []byte, aux uint64) ([]byte, error) {
	if len(q) == 0 {
		return nil, errors.New("empty modulus q")
	}
	if p0 == nil {
		return nil, errors.New("nil paillier P0")
	}
	if len(c0) == 0 {
		return nil, errors.New("empty ciphertext c0")
	}
	if p1 == nil {
		return nil, errors.New("nil paillier P1")
	}
	if len(c1) == 0 {
		return nil, errors.New("empty ciphertext c1")
	}
	if len(x) == 0 {
		return nil, errors.New("empty plaintext x")
	}
	if len(r0) == 0 {
		return nil, errors.New("empty randomness r0")
	}
	if len(r1) == 0 {
		return nil, errors.New("empty randomness r1")
	}
	if len(sessionID) == 0 {
		return nil, errors.New("empty session ID")
	}

	qMem := goBytesToCmem(q)
	c0Mem := goBytesToCmem(c0)
	c1Mem := goBytesToCmem(c1)
	xMem := goBytesToCmem(x)
	r0Mem := goBytesToCmem(r0)
	r1Mem := goBytesToCmem(r1)
	sessionIDMem := goBytesToCmem(sessionID)

	var out C.cmem_t
	rc := C.cbmpc_two_paillier_equal_prove(qMem, p0, c0Mem, p1, c1Mem, xMem, r0Mem, r1Mem, sessionIDMem, C.uint64_t(aux), &out)
	if rc != 0 {
		return nil, formatNativeErr("two_paillier_equal_prove", rc)
	}

	return cmemToGoBytes(out), nil
}

// TwoPaillierEqualVerify verifies a Two_Paillier_Equal proof.
// The proof parameter should be serialized proof bytes.
func TwoPaillierEqualVerify(proof, q []byte, p0 Paillier, c0 []byte, p1 Paillier, c1, sessionID []byte, aux uint64) error {
	if len(proof) == 0 {
		return errors.New("empty proof")
	}
	if len(q) == 0 {
		return errors.New("empty modulus q")
	}
	if p0 == nil {
		return errors.New("nil paillier P0")
	}
	if len(c0) == 0 {
		return errors.New("empty ciphertext c0")
	}
	if p1 == nil {
		return errors.New("nil paillier P1")
	}
	if len(c1) == 0 {
		return errors.New("empty ciphertext c1")
	}
	if len(sessionID) == 0 {
		return errors.New("empty session ID")
	}

	proofMem := goBytesToCmem(proof)
	qMem := goBytesToCmem(q)
	c0Mem := goBytesToCmem(c0)
	c1Mem := goBytesToCmem(c1)
	sessionIDMem := goBytesToCmem(sessionID)

	rc := C.cbmpc_two_paillier_equal_verify(proofMem, qMem, p0, c0Mem, p1, c1Mem, sessionIDMem, C.uint64_t(aux))
	if rc != 0 {
		return formatNativeErr("two_paillier_equal_verify", rc)
	}

	return nil
}

// =====================
// ZK Proof Operations - Paillier_Range_Exp_Slack
// =====================

// PaillierRangeExpSlackProve creates a Paillier_Range_Exp_Slack proof for proving that
// a ciphertext encrypts a value within a valid range with slack.
// Returns the serialized proof as bytes.
func PaillierRangeExpSlackProve(paillier Paillier, q, c, x, r, sessionID []byte, aux uint64) ([]byte, error) {
	if paillier == nil {
		return nil, errors.New("nil paillier")
	}
	if len(q) == 0 {
		return nil, errors.New("empty modulus q")
	}
	if len(c) == 0 {
		return nil, errors.New("empty ciphertext")
	}
	if len(x) == 0 {
		return nil, errors.New("empty plaintext")
	}
	if len(r) == 0 {
		return nil, errors.New("empty randomness")
	}
	if len(sessionID) == 0 {
		return nil, errors.New("empty session ID")
	}

	qMem := goBytesToCmem(q)
	cMem := goBytesToCmem(c)
	xMem := goBytesToCmem(x)
	rMem := goBytesToCmem(r)
	sessionIDMem := goBytesToCmem(sessionID)

	var out C.cmem_t
	rc := C.cbmpc_paillier_range_exp_slack_prove(paillier, qMem, cMem, xMem, rMem, sessionIDMem, C.uint64_t(aux), &out)
	if rc != 0 {
		return nil, formatNativeErr("paillier_range_exp_slack_prove", rc)
	}

	return cmemToGoBytes(out), nil
}

// PaillierRangeExpSlackVerify verifies a Paillier_Range_Exp_Slack proof.
// The proof parameter should be serialized proof bytes.
func PaillierRangeExpSlackVerify(proof []byte, paillier Paillier, q, c, sessionID []byte, aux uint64) error {
	if len(proof) == 0 {
		return errors.New("empty proof")
	}
	if paillier == nil {
		return errors.New("nil paillier")
	}
	if len(q) == 0 {
		return errors.New("empty modulus q")
	}
	if len(c) == 0 {
		return errors.New("empty ciphertext")
	}
	if len(sessionID) == 0 {
		return errors.New("empty session ID")
	}

	proofMem := goBytesToCmem(proof)
	qMem := goBytesToCmem(q)
	cMem := goBytesToCmem(c)
	sessionIDMem := goBytesToCmem(sessionID)

	rc := C.cbmpc_paillier_range_exp_slack_verify(proofMem, paillier, qMem, cMem, sessionIDMem, C.uint64_t(aux))
	if rc != 0 {
		return formatNativeErr("paillier_range_exp_slack_verify", rc)
	}

	return nil
}

// =====================
// Access Control (AC) Builder Operations
// =====================

// ACNode is an opaque handle to a C++ ac_owned_t node.
type ACNode = C.cbmpc_ac_node

// ACLeaf creates a leaf node with the given party name.
// The returned node must be freed with ACNodeFree unless it's added as a child
// (parent nodes take ownership).
func ACLeaf(name []byte) (ACNode, error) {
	if len(name) == 0 {
		return nil, errors.New("empty name")
	}

	nameMem := goBytesToCmem(name)
	var node ACNode
	rc := C.cbmpc_ac_leaf(nameMem, &node)
	if rc != 0 {
		return nil, formatNativeErr("ac_leaf", rc)
	}

	return node, nil
}

// ACAnd creates an AND node with the given children.
// Takes ownership of children - caller must NOT free them after this call.
// The returned node must be freed with ACNodeFree.
func ACAnd(children []ACNode) (ACNode, error) {
	if len(children) == 0 {
		return nil, errors.New("empty children")
	}

	// Convert []ACNode to C array
	cChildren := make([]C.cbmpc_ac_node, len(children))
	for i, child := range children {
		if child == nil {
			return nil, errors.New("nil child in children array")
		}
		cChildren[i] = child
	}

	var node ACNode
	rc := C.cbmpc_ac_and(&cChildren[0], C.int(len(cChildren)), &node)
	if rc != 0 {
		return nil, formatNativeErr("ac_and", rc)
	}

	return node, nil
}

// ACOr creates an OR node with the given children.
// Takes ownership of children - caller must NOT free them after this call.
// The returned node must be freed with ACNodeFree.
func ACOr(children []ACNode) (ACNode, error) {
	if len(children) == 0 {
		return nil, errors.New("empty children")
	}

	// Convert []ACNode to C array
	cChildren := make([]C.cbmpc_ac_node, len(children))
	for i, child := range children {
		if child == nil {
			return nil, errors.New("nil child in children array")
		}
		cChildren[i] = child
	}

	var node ACNode
	rc := C.cbmpc_ac_or(&cChildren[0], C.int(len(cChildren)), &node)
	if rc != 0 {
		return nil, formatNativeErr("ac_or", rc)
	}

	return node, nil
}

// ACThreshold creates a threshold node requiring k of n children.
// Takes ownership of children - caller must NOT free them after this call.
// The returned node must be freed with ACNodeFree.
func ACThreshold(k int, children []ACNode) (ACNode, error) {
	if k <= 0 {
		return nil, errors.New("threshold k must be positive")
	}
	if len(children) == 0 {
		return nil, errors.New("empty children")
	}
	if k > len(children) {
		return nil, errors.New("threshold k exceeds number of children")
	}

	// Convert []ACNode to C array
	cChildren := make([]C.cbmpc_ac_node, len(children))
	for i, child := range children {
		if child == nil {
			return nil, errors.New("nil child in children array")
		}
		cChildren[i] = child
	}

	var node ACNode
	rc := C.cbmpc_ac_threshold(C.int(k), &cChildren[0], C.int(len(cChildren)), &node)
	if rc != 0 {
		return nil, formatNativeErr("ac_threshold", rc)
	}

	return node, nil
}

// ACSerialize serializes an AC node tree to bytes.
// Returns the serialized ac_owned_t bytes.
func ACSerialize(node ACNode) ([]byte, error) {
	if node == nil {
		return nil, errors.New("nil node")
	}

	var out C.cmem_t
	rc := C.cbmpc_ac_serialize(node, &out)
	if rc != 0 {
		return nil, formatNativeErr("ac_serialize", rc)
	}

	return cmemToGoBytes(out), nil
}

// ACToString converts an AC to a canonical string representation (for debugging).
func ACToString(acBytes []byte) (string, error) {
	if len(acBytes) == 0 {
		return "", errors.New("empty AC bytes")
	}

	acMem := goBytesToCmem(acBytes)
	var out C.cmem_t
	rc := C.cbmpc_ac_to_string(acMem, &out)
	if rc != 0 {
		return "", formatNativeErr("ac_to_string", rc)
	}

	strBytes := cmemToGoBytes(out)
	return string(strBytes), nil
}

// ACListLeafPaths returns the list of leaf paths from an AC structure.
// These paths can be used as keys in the pathToEK map for PVE-AC operations.
func ACListLeafPaths(acBytes []byte) ([]string, error) {
	if len(acBytes) == 0 {
		return nil, errors.New("empty AC bytes")
	}

	acMem := goBytesToCmem(acBytes)
	var out C.cmems_t
	rc := C.cbmpc_ac_list_leaf_paths(acMem, &out)
	if rc != 0 {
		return nil, formatNativeErr("ac_list_leaf_paths", rc)
	}

	pathBytes := cmemsToGoByteSlices(out)
	paths := make([]string, len(pathBytes))
	for i, pb := range pathBytes {
		paths[i] = string(pb)
	}
	return paths, nil
}

// ACNodeFree frees an AC node (and its entire subtree).
func ACNodeFree(node ACNode) {
	if node != nil {
		C.cbmpc_ac_node_free(node)
	}
}

// =====================
// PVE-AC Operations
// =====================

// PVEACEncrypt encrypts multiple scalars using PVE with access control.
// The provided KEM is bound to thread-local storage for the duration of the call.
// pathToEK maps party path names to encryption key bytes.
func PVEACEncrypt(k KEM, acBytes []byte, pathToEK map[string][]byte, label []byte, curveNID int, xScalarsBytes [][]byte) ([]byte, error) {
	if len(acBytes) == 0 {
		return nil, errors.New("empty AC bytes")
	}
	if len(pathToEK) == 0 {
		return nil, errors.New("empty path to EK map")
	}
	if len(label) == 0 {
		return nil, errors.New("empty label")
	}
	if len(xScalarsBytes) == 0 {
		return nil, errors.New("empty x scalars")
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

	// Convert map to parallel slices
	paths := make([][]byte, 0, len(pathToEK))
	eks := make([][]byte, 0, len(pathToEK))
	for path, ek := range pathToEK {
		paths = append(paths, []byte(path))
		eks = append(eks, ek)
	}

	acMem := goBytesToCmem(acBytes)
	pathsMem := goBytesSliceToCmems(paths)
	defer freeCmems(pathsMem)
	eksMem := goBytesSliceToCmems(eks)
	defer freeCmems(eksMem)
	labelMem := goBytesToCmem(label)
	xScalarsMem := goBytesSliceToCmems(xScalarsBytes)
	defer freeCmems(xScalarsMem)

	var out C.cmem_t
	rc := C.cbmpc_pve_ac_encrypt(acMem, pathsMem, eksMem, labelMem, C.int(curveNID), xScalarsMem, &out)
	if rc != 0 {
		return nil, formatNativeErr("pve_ac_encrypt", rc)
	}

	return cmemToGoBytes(out), nil
}

// PVEACVerify verifies a PVE-AC ciphertext against public key points.
// The provided KEM is bound to thread-local storage for the duration of the call.
// pathToEK maps party path names to encryption key bytes.
func PVEACVerify(k KEM, acBytes []byte, pathToEK map[string][]byte, pveCT []byte, qPoints []ECCPoint, label []byte) error {
	if len(acBytes) == 0 {
		return errors.New("empty AC bytes")
	}
	if len(pathToEK) == 0 {
		return errors.New("empty path to EK map")
	}
	if len(pveCT) == 0 {
		return errors.New("empty PVE ciphertext")
	}
	if len(qPoints) == 0 {
		return errors.New("empty Q points")
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

	// Convert map to parallel slices
	paths := make([][]byte, 0, len(pathToEK))
	eks := make([][]byte, 0, len(pathToEK))
	for path, ek := range pathToEK {
		paths = append(paths, []byte(path))
		eks = append(eks, ek)
	}

	// Convert []ECCPoint to C array
	cPoints := make([]C.cbmpc_ecc_point, len(qPoints))
	for i, p := range qPoints {
		if p == nil {
			return errors.New("nil point in Q points array")
		}
		cPoints[i] = p
	}

	acMem := goBytesToCmem(acBytes)
	pathsMem := goBytesSliceToCmems(paths)
	defer freeCmems(pathsMem)
	eksMem := goBytesSliceToCmems(eks)
	defer freeCmems(eksMem)
	pveCTMem := goBytesToCmem(pveCT)
	labelMem := goBytesToCmem(label)

	rc := C.cbmpc_pve_ac_verify(acMem, pathsMem, eksMem, pveCTMem, &cPoints[0], C.int(len(cPoints)), labelMem)
	if rc != 0 {
		return formatNativeErr("pve_ac_verify", rc)
	}

	return nil
}

// PVEACPartyDecryptRow performs party decryption for a single row to produce a share.
// The provided KEM is bound to thread-local storage for the duration of the call.
func PVEACPartyDecryptRow(k KEM, acBytes []byte, rowIndex int, path string, dkHandle unsafe.Pointer, pveCT, label []byte) ([]byte, error) {
	if len(acBytes) == 0 {
		return nil, errors.New("empty AC bytes")
	}
	if rowIndex < 0 {
		return nil, errors.New("negative row index")
	}
	if len(path) == 0 {
		return nil, errors.New("empty path")
	}
	if dkHandle == nil {
		return nil, errors.New("nil dk handle")
	}
	if len(pveCT) == 0 {
		return nil, errors.New("empty PVE ciphertext")
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

	acMem := goBytesToCmem(acBytes)
	pathMem := goBytesToCmem([]byte(path))
	pveCTMem := goBytesToCmem(pveCT)
	labelMem := goBytesToCmem(label)

	var out C.cmem_t
	rc := C.cbmpc_pve_ac_party_decrypt_row(acMem, C.int(rowIndex), pathMem, dkHandle, pveCTMem, labelMem, &out)
	if rc != 0 {
		return nil, formatNativeErr("pve_ac_party_decrypt_row", rc)
	}

	return cmemToGoBytes(out), nil
}

// PVEACAggregateToRestoreRow aggregates quorum shares to restore the original scalars for a row.
// The provided KEM is bound to thread-local storage for the duration of the call.
// If allPathToEK is provided and non-empty, verification is performed during aggregation.
func PVEACAggregateToRestoreRow(k KEM, acBytes []byte, rowIndex int, label []byte, quorumPathToShare map[string][]byte, pveCT []byte, allPathToEK map[string][]byte) ([][]byte, error) {
	if len(acBytes) == 0 {
		return nil, errors.New("empty AC bytes")
	}
	if rowIndex < 0 {
		return nil, errors.New("negative row index")
	}
	if len(label) == 0 {
		return nil, errors.New("empty label")
	}
	if len(quorumPathToShare) == 0 {
		return nil, errors.New("empty quorum path to share map")
	}
	if len(pveCT) == 0 {
		return nil, errors.New("empty PVE ciphertext")
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

	// Convert quorum map to parallel slices
	quorumPaths := make([][]byte, 0, len(quorumPathToShare))
	quorumShares := make([][]byte, 0, len(quorumPathToShare))
	for path, share := range quorumPathToShare {
		quorumPaths = append(quorumPaths, []byte(path))
		quorumShares = append(quorumShares, share)
	}

	acMem := goBytesToCmem(acBytes)
	labelMem := goBytesToCmem(label)
	quorumPathsMem := goBytesSliceToCmems(quorumPaths)
	defer freeCmems(quorumPathsMem)
	quorumSharesMem := goBytesSliceToCmems(quorumShares)
	defer freeCmems(quorumSharesMem)
	pveCTMem := goBytesToCmem(pveCT)

	// Convert allPathToEK map if provided
	var allPathsMem, allEksMem C.cmems_t
	if len(allPathToEK) > 0 {
		allPaths := make([][]byte, 0, len(allPathToEK))
		allEks := make([][]byte, 0, len(allPathToEK))
		for path, ek := range allPathToEK {
			allPaths = append(allPaths, []byte(path))
			allEks = append(allEks, ek)
		}
		allPathsMem = goBytesSliceToCmems(allPaths)
		defer freeCmems(allPathsMem)
		allEksMem = goBytesSliceToCmems(allEks)
		defer freeCmems(allEksMem)
	}

	var out C.cmems_t
	rc := C.cbmpc_pve_ac_aggregate_to_restore_row(acMem, C.int(rowIndex), labelMem, quorumPathsMem, quorumSharesMem, pveCTMem, allPathsMem, allEksMem, &out)
	if rc != 0 {
		return nil, formatNativeErr("pve_ac_aggregate_to_restore_row", rc)
	}

	return cmemsToGoByteSlices(out), nil
}
