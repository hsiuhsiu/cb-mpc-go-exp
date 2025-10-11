//go:build cgo && !windows

package backend

/*
#include <stdlib.h>
#include <string.h>
#include "capi.h"
#include "cbmpc/crypto/pki_ffi.h"
*/
import "C"

import (
	"errors"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"unsafe"

	"github.com/coinbase/cb-mpc-go/pkg/cbmpc/kem"
)

// ECCPoint is a type alias for C.cbmpc_ecc_point
type ECCPoint = C.cbmpc_ecc_point

// KEM is a type alias for kem.KEM.
// This allows the backend to use the public KEM interface without importing it everywhere.
type KEM = kem.KEM

// kemRegistry maps goroutine IDs to KEM implementations.
// This allows concurrent PVE operations with different KEMs.
var (
	kemRegistry   = make(map[int64]KEM)
	kemRegistryMu sync.RWMutex
)

// getGoroutineID returns the current goroutine ID.
// This is used to associate KEMs with specific goroutines.
func getGoroutineID() int64 {
	var buf [64]byte
	n := runtime.Stack(buf[:], false)
	idField := strings.Fields(strings.TrimPrefix(string(buf[:n]), "goroutine "))[0]
	id, _ := strconv.ParseInt(idField, 10, 64)
	return id
}

// setKEMForGoroutine registers a KEM for the current goroutine.
func setKEMForGoroutine(kem KEM) int64 {
	gid := getGoroutineID()
	kemRegistryMu.Lock()
	kemRegistry[gid] = kem
	kemRegistryMu.Unlock()
	return gid
}

// clearKEMForGoroutine removes the KEM registration for a goroutine.
func clearKEMForGoroutine(gid int64) {
	kemRegistryMu.Lock()
	delete(kemRegistry, gid)
	kemRegistryMu.Unlock()
}

// getKEMForGoroutine retrieves the KEM for the current goroutine.
func getKEMForGoroutine() KEM {
	gid := getGoroutineID()
	kemRegistryMu.RLock()
	kem := kemRegistry[gid]
	kemRegistryMu.RUnlock()
	return kem
}

// handleRegistry stores Go objects that need to be passed through C as opaque handles.
// This allows us to pass handles through C++ without violating CGO pointer rules.
var (
	handleRegistryMu sync.RWMutex
	handleRegistry   = make(map[uint64]any)
	nextHandleID     = uint64(0xDEADBEEF0000) // Start high to avoid looking like valid pointers
)

// registerHandle stores a Go object and returns a CGO-safe handle ID.
func registerHandle(obj any) unsafe.Pointer {
	handleRegistryMu.Lock()
	defer handleRegistryMu.Unlock()

	id := nextHandleID
	nextHandleID++
	handleRegistry[id] = obj

	//nolint:govet // Converting uintptr to unsafe.Pointer is intentional for CGO handle passing
	return unsafe.Pointer(uintptr(id))
}

// lookupHandle retrieves a Go object from a handle ID.
func lookupHandle(handle unsafe.Pointer) (any, bool) {
	if handle == nil {
		return nil, false
	}

	id := uint64(uintptr(handle))

	handleRegistryMu.RLock()
	defer handleRegistryMu.RUnlock()

	obj, exists := handleRegistry[id]
	return obj, exists
}

// freeHandle removes a Go object from the registry.
func freeHandle(handle unsafe.Pointer) {
	if handle == nil {
		return
	}

	id := uint64(uintptr(handle))

	handleRegistryMu.Lock()
	defer handleRegistryMu.Unlock()

	delete(handleRegistry, id)
}

// SetKEM registers a KEM implementation for the current goroutine.
// Returns a cleanup function that must be called when the operation completes.
// This allows concurrent PVE operations with different KEMs.
//
// Usage:
//
//	cleanup := bindings.SetKEM(kem)
//	defer cleanup()
//	// ... perform PVE operations ...
func SetKEM(kem KEM) func() {
	gid := setKEMForGoroutine(kem)
	return func() {
		clearKEMForGoroutine(gid)
	}
}

// GetKEM returns the KEM implementation for the current goroutine.
func GetKEM() KEM {
	return getKEMForGoroutine()
}

//export go_ffi_kem_encap
func go_ffi_kem_encap(ek_bytes C.cmem_t, rho C.cmem_t, kem_ct_out *C.cmem_t, kem_ss_out *C.cmem_t) C.int {
	if kem_ct_out == nil || kem_ss_out == nil {
		return C.int(1)
	}

	kem := GetKEM()
	if kem == nil {
		return C.int(1)
	}

	// Convert inputs to Go
	ek := C.GoBytes(unsafe.Pointer(ek_bytes.data), ek_bytes.size)
	rhoBytes := C.GoBytes(unsafe.Pointer(rho.data), rho.size)
	if len(rhoBytes) != 32 {
		return C.int(1)
	}

	var rho32 [32]byte
	copy(rho32[:], rhoBytes)

	// Call Go KEM
	ct, ss, err := kem.Encapsulate(ek, rho32)
	if err != nil {
		return C.int(1)
	}

	// Allocate and copy outputs
	ct_cmem := allocCmem(ct)
	ss_cmem := allocCmem(ss)

	*kem_ct_out = ct_cmem
	*kem_ss_out = ss_cmem

	return C.int(0)
}

//export go_ffi_kem_decap
func go_ffi_kem_decap(dk_handle unsafe.Pointer, kem_ct C.cmem_t, kem_ss_out *C.cmem_t) C.int {
	if dk_handle == nil || kem_ss_out == nil {
		return C.int(1)
	}

	kem := GetKEM()
	if kem == nil {
		return C.int(1)
	}

	// Look up the actual Go object from the handle registry
	skHandle, exists := lookupHandle(dk_handle)
	if !exists {
		return C.int(1)
	}

	// Convert ciphertext to Go
	ct := C.GoBytes(unsafe.Pointer(kem_ct.data), kem_ct.size)

	// Call Go KEM with the actual Go object
	ss, err := kem.Decapsulate(skHandle, ct)
	if err != nil {
		return C.int(1)
	}

	// Allocate and copy output
	ss_cmem := allocCmem(ss)
	*kem_ss_out = ss_cmem

	return C.int(0)
}

//export go_ffi_kem_dk_to_ek
func go_ffi_kem_dk_to_ek(dk_handle unsafe.Pointer, ek_bytes_out *C.cmem_t) C.int {
	if dk_handle == nil || ek_bytes_out == nil {
		return C.int(1)
	}

	kem := GetKEM()
	if kem == nil {
		return C.int(1)
	}

	// The dk_handle is an opaque pointer managed by the KEM implementation.
	// We need to get the KEM to extract the public key from this handle.
	// Unfortunately, the KEM interface doesn't have a method to do this directly.
	// The DerivePub method expects skRef (serialized), not the handle.
	//
	// For now, we'll return an error since this callback shouldn't be needed
	// for decryption - it's only needed if the C++ code needs to derive ek from dk.
	// In our PVE usage, we always pass both ek and dk explicitly.
	return C.int(1) // Not implemented
}

// allocCmem allocates C memory and copies Go bytes into it.
// The caller is responsible for freeing this memory.
func allocCmem(data []byte) C.cmem_t {
	var cmem C.cmem_t
	if len(data) == 0 {
		cmem.data = nil
		cmem.size = 0
		return cmem
	}

	cmem.size = C.int(len(data))
	cmem.data = (*C.uint8_t)(C.malloc(C.size_t(len(data))))
	if cmem.data != nil {
		C.memcpy(unsafe.Pointer(cmem.data), unsafe.Pointer(&data[0]), C.size_t(len(data)))
	}
	return cmem
}

// PVEEncrypt is a C binding wrapper for PVE encrypt.
func PVEEncrypt(ekBytes, label []byte, curveNID int, xBytes []byte) ([]byte, error) {
	if len(ekBytes) == 0 {
		return nil, errors.New("empty ek bytes")
	}
	if len(label) == 0 {
		return nil, errors.New("empty label")
	}
	if len(xBytes) == 0 {
		return nil, errors.New("empty x bytes")
	}

	ekMem := goBytesToCmem(ekBytes)
	labelMem := goBytesToCmem(label)
	xMem := goBytesToCmem(xBytes)

	var out C.cmem_t
	rc := C.cbmpc_pve_encrypt(ekMem, labelMem, C.int(curveNID), xMem, &out)
	if rc != 0 {
		return nil, errors.New("pve_encrypt failed")
	}

	return cmemToGoBytes(out), nil
}

// PVEDecrypt is a C binding wrapper for PVE decrypt.
func PVEDecrypt(dkHandle unsafe.Pointer, ekBytes, pveCT, label []byte, curveNID int) ([]byte, error) {
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

	ekMem := goBytesToCmem(ekBytes)
	pveCTMem := goBytesToCmem(pveCT)
	labelMem := goBytesToCmem(label)

	var out C.cmem_t
	// The dkHandle is an opaque identifier (not a Go pointer) that will be passed through
	// C++ back to Go callbacks. C++ only stores and passes it, never dereferences it.
	// The actual handle lookup happens in the Go KEM implementation.
	rc := C.cbmpc_pve_decrypt(dkHandle, ekMem, pveCTMem, labelMem, C.int(curveNID), &out)
	if rc != 0 {
		return nil, errors.New("pve_decrypt failed")
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
		return nil, errors.New("pve_get_label failed")
	}

	return cmemToGoBytes(out), nil
}

// ScalarFromBytes creates a Scalar from bytes (big-endian).
func ScalarFromBytes(bytes []byte) (unsafe.Pointer, error) {
	if len(bytes) == 0 {
		return nil, errors.New("empty bytes")
	}

	bytesMem := goBytesToCmem(bytes)

	var out C.cmem_t
	rc := C.cbmpc_scalar_from_bytes(bytesMem, &out)
	if rc != 0 {
		return nil, errors.New("scalar_from_bytes failed")
	}

	return unsafe.Pointer(out.data), nil
}

// ScalarFromString creates a Scalar from a decimal string.
func ScalarFromString(str string) (unsafe.Pointer, error) {
	if len(str) == 0 {
		return nil, errors.New("empty string")
	}

	cstr := C.CString(str)
	defer C.free(unsafe.Pointer(cstr))

	var out C.cmem_t
	rc := C.cbmpc_scalar_from_string(cstr, &out)
	if rc != 0 {
		return nil, errors.New("scalar_from_string failed")
	}

	return unsafe.Pointer(out.data), nil
}

// ScalarToBytes serializes a Scalar to bytes (big-endian).
func ScalarToBytes(scalar unsafe.Pointer) ([]byte, error) {
	if scalar == nil {
		return nil, errors.New("nil scalar")
	}

	scalarMem := C.cmem_t{
		data: (*C.uint8_t)(scalar),
		size: 0, // Size 0 indicates opaque pointer
	}

	var out C.cmem_t
	rc := C.cbmpc_scalar_to_bytes(scalarMem, &out)
	if rc != 0 {
		return nil, errors.New("scalar_to_bytes failed")
	}

	return cmemToGoBytes(out), nil
}

// ScalarFree frees a Scalar.
func ScalarFree(scalar unsafe.Pointer) {
	if scalar != nil {
		scalarMem := C.cmem_t{
			data: (*C.uint8_t)(scalar),
			size: 0, // Size 0 indicates opaque pointer
		}
		C.cbmpc_scalar_free(scalarMem)
	}
}

// RegisterHandle stores a Go object and returns a CGO-safe handle.
// This is used for passing Go objects through C code without violating CGO pointer rules.
func RegisterHandle(obj any) unsafe.Pointer {
	return registerHandle(obj)
}

// FreeHandle removes a Go object from the handle registry.
func FreeHandle(handle unsafe.Pointer) {
	freeHandle(handle)
}

// ECCPointFromBytes creates an ECC point from compressed bytes.
// Returns an ECCPoint that must be freed with ECCPointFree.
func ECCPointFromBytes(curveNID int, bytes []byte) (ECCPoint, error) {
	if len(bytes) == 0 {
		return nil, errors.New("empty bytes")
	}

	bytesMem := goBytesToCmem(bytes)

	var point ECCPoint
	rc := C.cbmpc_ecc_point_from_bytes(C.int(curveNID), bytesMem, &point)
	if rc != 0 {
		return nil, errors.New("ecc_point_from_bytes failed")
	}

	return point, nil
}

// ECCPointToBytes serializes an ECC point to compressed bytes.
func ECCPointToBytes(point ECCPoint) ([]byte, error) {
	if point == nil {
		return nil, errors.New("nil point")
	}

	var out C.cmem_t
	rc := C.cbmpc_ecc_point_to_bytes(point, &out)
	if rc != 0 {
		return nil, errors.New("ecc_point_to_bytes failed")
	}

	return cmemToGoBytes(out), nil
}

// ECCPointFree frees an ECC point.
func ECCPointFree(point ECCPoint) {
	if point != nil {
		C.cbmpc_ecc_point_free(point)
	}
}

// ECCPointGetCurve returns the curve for an ECC point.
// Returns backend.Curve enum directly, not NID.
func ECCPointGetCurve(point ECCPoint) Curve {
	if point == nil {
		return Unknown
	}
	return Curve(C.cbmpc_ecc_point_get_curve(point))
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
		return nil, errors.New("pve_get_Q_point failed")
	}

	return point, nil
}

// PVEVerifyWithPoint verifies a PVE ciphertext using an ecc_point_t directly.
// This is more efficient than PVEVerify as it avoids serialization/deserialization.
//
//nolint:gocritic // QPoint follows Go convention for acronym capitalization
func PVEVerifyWithPoint(ekBytes, pveCT []byte, QPoint ECCPoint, label []byte) error {
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

	ekMem := goBytesToCmem(ekBytes)
	pveCTMem := goBytesToCmem(pveCT)
	labelMem := goBytesToCmem(label)

	rc := C.cbmpc_pve_verify_with_point(ekMem, pveCTMem, QPoint, labelMem)
	if rc != 0 {
		return errors.New("pve_verify failed")
	}

	return nil
}
