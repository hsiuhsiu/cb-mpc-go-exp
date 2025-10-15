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
