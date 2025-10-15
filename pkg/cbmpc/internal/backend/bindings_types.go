//go:build cgo && !windows

package backend

/*
#include <stdlib.h>
#include <string.h>
#include "cbmpc/core/cmem.h"
#include "ctypes.h"
#include "capi.h"
*/
import "C"

import (
	"errors"
	"sync"
	"unsafe"
)

// Error codes from cb-mpc
const (
	E_ECDSA_2P_BIT_LEAK = 0xff040002 // Bit leak detected in signature verification
)

// cmemToGoBytes converts a C.cmem_t to a Go []byte slice and takes ownership of the C memory.
// Securely zeros and frees the C memory. Caller must not access the C memory after calling.
//
// This is the primary function for converting C++ outputs to Go. Used in Patterns 1, 2, and 3.
// See CLAUDE.md "Type Conversion Patterns" for usage guidelines.
func cmemToGoBytes(cmem C.cmem_t) []byte {
	if cmem.data == nil || cmem.size <= 0 {
		return nil
	}

	result := C.GoBytes(unsafe.Pointer(cmem.data), cmem.size)

	if cmem.size > 0 {
		C.memset(unsafe.Pointer(cmem.data), 0, C.size_t(cmem.size))
	}
	C.free(unsafe.Pointer(cmem.data))

	return result
}

// cmemsToGoByteSlices converts a C.cmems_t to a Go [][]byte slice and takes ownership of the C memory.
// Securely zeros and frees the C memory. Caller must not access the C memory after calling.
//
// Used for converting std::vector<buf_t> outputs to Go. See Pattern 2 in CLAUDE.md.
func cmemsToGoByteSlices(cmems C.cmems_t) [][]byte {
	if cmems.count <= 0 {
		return nil
	}

	// Convert the C array of sizes to a Go slice
	cSizesArray := (*[1 << 30]C.int)(unsafe.Pointer(cmems.sizes))[:cmems.count:cmems.count]

	result := make([][]byte, cmems.count)
	offset := 0
	for i := range result {
		size := int(cSizesArray[i])
		if size > 0 && cmems.data != nil {
			// Copy the data for this element
			result[i] = C.GoBytes(unsafe.Pointer(uintptr(unsafe.Pointer(cmems.data))+uintptr(offset)), C.int(size))
			offset += size
		}
	}

	// Securely zero and free the memory
	if cmems.data != nil && offset > 0 {
		C.memset(unsafe.Pointer(cmems.data), 0, C.size_t(offset))
		C.free(unsafe.Pointer(cmems.data))
	}
	if cmems.sizes != nil {
		C.free(unsafe.Pointer(cmems.sizes))
	}

	return result
}

// goBytesToCmem converts a Go []byte slice to a C.cmem_t.
// The returned cmem_t points directly to Go memory and is only valid for the duration
// of the CGO call. The caller must not retain the cmem_t beyond the CGO call.
//
// IMPORTANT: Use this for FAST, SYNCHRONOUS C operations only (e.g., DKG, deserialization).
// For long-running operations (e.g., Sign), use allocCmem + defer freeCmem instead.
// See "Go to C Memory Conversion" in CLAUDE.md for decision criteria.
func goBytesToCmem(data []byte) C.cmem_t {
	var cmem C.cmem_t
	cmem.size = C.int(len(data))
	if len(data) > 0 {
		cmem.data = (*C.uint8_t)(unsafe.Pointer(&data[0]))
	} else {
		cmem.data = nil
	}
	return cmem
}

// goBytesSliceToCmems converts a Go [][]byte slice to a C.cmems_t.
// The returned cmems_t points to allocated C memory that must be freed with freeCmems.
//
// Used for passing multiple buffers to C (e.g., batch operations).
// Always pair with defer freeCmems() to ensure cleanup.
func goBytesSliceToCmems(slices [][]byte) C.cmems_t {
	var cmems C.cmems_t
	if len(slices) == 0 {
		cmems.data = nil
		cmems.sizes = nil
		cmems.count = 0
		return cmems
	}

	// Calculate total size
	totalSize := 0
	for _, slice := range slices {
		totalSize += len(slice)
	}

	// Allocate contiguous buffer for all data
	var data *C.uint8_t
	if totalSize > 0 {
		data = (*C.uint8_t)(C.malloc(C.size_t(totalSize)))
	}

	// Allocate sizes array
	sizes := (*C.int)(C.malloc(C.size_t(len(slices)) * C.size_t(unsafe.Sizeof(C.int(0)))))

	// OOM check: if allocation failed for sizes or for data (when totalSize > 0),
	// return an empty cmems to signal error to the C side
	if sizes == nil || (totalSize > 0 && data == nil) {
		if data != nil {
			C.free(unsafe.Pointer(data))
		}
		cmems.data = nil
		cmems.sizes = nil
		cmems.count = 0
		return cmems
	}

	// Copy data and record sizes
	offset := 0
	for i, slice := range slices {
		sizePtr := (*C.int)(unsafe.Pointer(uintptr(unsafe.Pointer(sizes)) + uintptr(i)*unsafe.Sizeof(C.int(0))))
		*sizePtr = C.int(len(slice))

		if len(slice) > 0 && data != nil {
			C.memcpy(
				unsafe.Pointer(uintptr(unsafe.Pointer(data))+uintptr(offset)),
				unsafe.Pointer(&slice[0]),
				C.size_t(len(slice)),
			)
			offset += len(slice)
		}
	}

	cmems.data = data
	cmems.sizes = sizes
	cmems.count = C.int(len(slices))
	return cmems
}

// freeCmems frees a cmems_t allocated by goBytesSliceToCmems
func freeCmems(cmems C.cmems_t) {
	if cmems.data != nil {
		C.free(unsafe.Pointer(cmems.data))
	}
	if cmems.sizes != nil {
		C.free(unsafe.Pointer(cmems.sizes))
	}
}

// allocCmem allocates C memory and copies Go bytes into it.
// The caller is responsible for freeing this memory with freeCmem.
//
// IMPORTANT: Use this for LONG-RUNNING C operations (e.g., Sign, multi-round protocols)
// where Go GC might move memory during execution. Always pair with defer freeCmem().
// See "Go to C Memory Conversion" in CLAUDE.md for decision criteria.
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

// freeCmem securely zeros and frees a C-allocated cmem_t buffer.
// Only use this on cmem values allocated by allocCmem. Do not call this
// on cmem values that point into Go memory (e.g., produced by goBytesToCmem).
func freeCmem(cmem C.cmem_t) {
	if cmem.data != nil && cmem.size > 0 {
		C.memset(unsafe.Pointer(cmem.data), 0, C.size_t(cmem.size))
		C.free(unsafe.Pointer(cmem.data))
	}
}

// =====================
// ECDSA 2P Key bridging
// =====================

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

// ECDSA2PKeyGetCurve gets the curve from an ECDSA 2P key.
// Returns backend.Curve enum directly, not NID.
func ECDSA2PKeyGetCurve(key ECDSA2PKey) (Curve, error) {
	if key == nil {
		return Unknown, errors.New("nil key")
	}

	var curveInt C.int
	rc := C.cbmpc_ecdsa2p_key_get_curve(key, &curveInt)
	if rc != 0 {
		return Unknown, errors.New("failed to get curve")
	}
	return Curve(curveInt), nil
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

// =====================
// ECDSA MP Key bridging
// =====================

// ECDSAMPKey is a type alias for *C.cbmpc_ecdsamp_key
type ECDSAMPKey = *C.cbmpc_ecdsamp_key

// ECDSAMPKeyFree frees an ECDSA MP key.
func ECDSAMPKeyFree(key ECDSAMPKey) {
	if key == nil {
		return
	}
	C.cbmpc_ecdsamp_key_free(key)
}

// ECDSAMPKeyGetPublicKey extracts the public key from an ECDSA MP key.
func ECDSAMPKeyGetPublicKey(key ECDSAMPKey) ([]byte, error) {
	if key == nil {
		return nil, errors.New("nil key")
	}

	var out C.cmem_t
	rc := C.cbmpc_ecdsamp_key_get_public_key(key, &out)
	if rc != 0 {
		return nil, errors.New("failed to get public key")
	}
	return cmemToGoBytes(out), nil
}

// ECDSAMPKeyGetCurve gets the curve from an ECDSA MP key.
// Returns backend.Curve enum directly, not NID.
func ECDSAMPKeyGetCurve(key ECDSAMPKey) (Curve, error) {
	if key == nil {
		return Unknown, errors.New("nil key")
	}

	var curveInt C.int
	rc := C.cbmpc_ecdsamp_key_get_curve(key, &curveInt)
	if rc != 0 {
		return Unknown, errors.New("failed to get curve")
	}
	return Curve(curveInt), nil
}

// ECDSAMPKeySerialize serializes an ECDSA MP key to bytes.
func ECDSAMPKeySerialize(key ECDSAMPKey) ([]byte, error) {
	if key == nil {
		return nil, errors.New("nil key")
	}

	var out C.cmem_t
	rc := C.cbmpc_ecdsamp_key_serialize(key, &out)
	if rc != 0 {
		return nil, errors.New("failed to serialize key")
	}
	return cmemToGoBytes(out), nil
}

// ECDSAMPKeyDeserialize deserializes an ECDSA MP key from bytes.
func ECDSAMPKeyDeserialize(data []byte) (ECDSAMPKey, error) {
	if len(data) == 0 {
		return nil, errors.New("empty data")
	}

	dataMem := goBytesToCmem(data)
	var key ECDSAMPKey
	rc := C.cbmpc_ecdsamp_key_deserialize(dataMem, &key)
	if rc != 0 {
		return nil, errors.New("failed to deserialize key")
	}
	return key, nil
}

// =====================
// Scalar bridging (bn_t)
// =====================

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

// =====================
// ECC Point bridging
// =====================

// ECCPoint is a type alias for C.cbmpc_ecc_point
type ECCPoint = C.cbmpc_ecc_point

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

// =====================
// EC ElGamal Commitment bridging
// =====================

// ECElGamalCommitment is a type alias for C.cbmpc_ec_elgamal_commitment
type ECElGamalCommitment = C.cbmpc_ec_elgamal_commitment

// ECElGamalCommitmentNew creates an EC ElGamal commitment from two points.
// Returns a commitment that must be freed with ECElGamalCommitmentFree.
func ECElGamalCommitmentNew(pointL, pointR ECCPoint) (ECElGamalCommitment, error) {
	if pointL == nil || pointR == nil {
		return nil, errors.New("nil point")
	}

	var commitment ECElGamalCommitment
	rc := C.cbmpc_ec_elgamal_commitment_new(pointL, pointR, &commitment)
	if rc != 0 {
		return nil, errors.New("ec_elgamal_commitment_new failed")
	}

	return commitment, nil
}

// ECElGamalCommitmentToBytes serializes an EC ElGamal commitment to bytes.
func ECElGamalCommitmentToBytes(commitment ECElGamalCommitment) ([]byte, error) {
	if commitment == nil {
		return nil, errors.New("nil commitment")
	}

	var out C.cmem_t
	rc := C.cbmpc_ec_elgamal_commitment_to_bytes(commitment, &out)
	if rc != 0 {
		return nil, errors.New("ec_elgamal_commitment_to_bytes failed")
	}

	return cmemToGoBytes(out), nil
}

// ECElGamalCommitmentFromBytes creates an EC ElGamal commitment from bytes.
// Returns a commitment that must be freed with ECElGamalCommitmentFree.
func ECElGamalCommitmentFromBytes(curveNID int, bytes []byte) (ECElGamalCommitment, error) {
	if len(bytes) == 0 {
		return nil, errors.New("empty bytes")
	}

	bytesMem := goBytesToCmem(bytes)

	var commitment ECElGamalCommitment
	rc := C.cbmpc_ec_elgamal_commitment_from_bytes(C.int(curveNID), bytesMem, &commitment)
	if rc != 0 {
		return nil, errors.New("ec_elgamal_commitment_from_bytes failed")
	}

	return commitment, nil
}

// ECElGamalCommitmentGetL gets the L point from a commitment.
// Returns a NEW point that must be freed with ECCPointFree.
func ECElGamalCommitmentGetL(commitment ECElGamalCommitment) (ECCPoint, error) {
	if commitment == nil {
		return nil, errors.New("nil commitment")
	}

	var point ECCPoint
	rc := C.cbmpc_ec_elgamal_commitment_get_L(commitment, &point)
	if rc != 0 {
		return nil, errors.New("ec_elgamal_commitment_get_L failed")
	}

	return point, nil
}

// ECElGamalCommitmentGetR gets the R point from a commitment.
// Returns a NEW point that must be freed with ECCPointFree.
func ECElGamalCommitmentGetR(commitment ECElGamalCommitment) (ECCPoint, error) {
	if commitment == nil {
		return nil, errors.New("nil commitment")
	}

	var point ECCPoint
	rc := C.cbmpc_ec_elgamal_commitment_get_R(commitment, &point)
	if rc != 0 {
		return nil, errors.New("ec_elgamal_commitment_get_R failed")
	}

	return point, nil
}

// ECElGamalCommitmentFree frees an EC ElGamal commitment.
func ECElGamalCommitmentFree(commitment ECElGamalCommitment) {
	if commitment != nil {
		C.cbmpc_ec_elgamal_commitment_free(commitment)
	}
}

// ECElGamalCommitmentMake creates an EC ElGamal commitment using make_commitment.
// Creates UV = (r*G, m*P + r*G) where P is the public key point.
// Returns a commitment that must be freed with ECElGamalCommitmentFree.
func ECElGamalCommitmentMake(p ECCPoint, m, r []byte) (ECElGamalCommitment, error) {
	if p == nil {
		return nil, errors.New("nil point P")
	}
	if len(m) == 0 || len(r) == 0 {
		return nil, errors.New("empty scalar")
	}

	mMem := goBytesToCmem(m)
	rMem := goBytesToCmem(r)

	var commitment ECElGamalCommitment
	rc := C.cbmpc_ec_elgamal_commitment_make(p, mMem, rMem, &commitment)
	if rc != 0 {
		return nil, formatNativeErr("ec_elgamal_commitment_make", rc)
	}

	return commitment, nil
}

// =====================
// Generic handle registry for opaque Go objects
// =====================

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

// RegisterHandle stores a Go object and returns a CGO-safe handle.
// This is used for passing Go objects through C code without violating CGO pointer rules.
func RegisterHandle(obj any) unsafe.Pointer {
	return registerHandle(obj)
}

// FreeHandle removes a Go object from the handle registry.
func FreeHandle(handle unsafe.Pointer) {
	freeHandle(handle)
}

// =====================
// Paillier cryptosystem bridging
// =====================

// Paillier is a type alias for C.cbmpc_paillier (opaque pointer to paillier_t).
type Paillier = C.cbmpc_paillier

// PaillierGenerate generates a new Paillier keypair (2048-bit modulus).
// Returns a Paillier instance that must be freed with PaillierFree.
func PaillierGenerate() (Paillier, error) {
	var paillier Paillier
	rc := C.cbmpc_paillier_generate(&paillier)
	if rc != 0 {
		return nil, formatNativeErr("paillier_generate", rc)
	}
	return paillier, nil
}

// PaillierCreatePub creates a Paillier instance from a public key (modulus n only).
// Returns a Paillier instance that must be freed with PaillierFree.
func PaillierCreatePub(n []byte) (Paillier, error) {
	if len(n) == 0 {
		return nil, errors.New("empty modulus n")
	}

	nMem := goBytesToCmem(n)
	var paillier Paillier
	rc := C.cbmpc_paillier_create_pub(nMem, &paillier)
	if rc != 0 {
		return nil, formatNativeErr("paillier_create_pub", rc)
	}
	return paillier, nil
}

// PaillierCreatePrv creates a Paillier instance from a private key (modulus n and factors p, q).
// Returns a Paillier instance that must be freed with PaillierFree.
func PaillierCreatePrv(n, p, q []byte) (Paillier, error) {
	if len(n) == 0 || len(p) == 0 || len(q) == 0 {
		return nil, errors.New("empty n, p, or q")
	}

	nMem := goBytesToCmem(n)
	pMem := goBytesToCmem(p)
	qMem := goBytesToCmem(q)

	var paillier Paillier
	rc := C.cbmpc_paillier_create_prv(nMem, pMem, qMem, &paillier)
	if rc != 0 {
		return nil, formatNativeErr("paillier_create_prv", rc)
	}
	return paillier, nil
}

// PaillierFree frees a Paillier instance.
func PaillierFree(paillier Paillier) {
	if paillier != nil {
		C.cbmpc_paillier_free(paillier)
	}
}

// PaillierHasPrivateKey checks if the Paillier instance has a private key.
func PaillierHasPrivateKey(paillier Paillier) bool {
	if paillier == nil {
		return false
	}
	return C.cbmpc_paillier_has_private_key(paillier) != 0
}

// PaillierGetN gets the modulus N from a Paillier instance.
func PaillierGetN(paillier Paillier) ([]byte, error) {
	if paillier == nil {
		return nil, errors.New("nil paillier")
	}

	var out C.cmem_t
	rc := C.cbmpc_paillier_get_N(paillier, &out)
	if rc != 0 {
		return nil, formatNativeErr("paillier_get_N", rc)
	}
	return cmemToGoBytes(out), nil
}

// PaillierEncrypt encrypts a plaintext value with the Paillier cryptosystem.
func PaillierEncrypt(paillier Paillier, plaintext []byte) ([]byte, error) {
	if paillier == nil {
		return nil, errors.New("nil paillier")
	}
	if len(plaintext) == 0 {
		return nil, errors.New("empty plaintext")
	}

	ptMem := goBytesToCmem(plaintext)
	var out C.cmem_t
	rc := C.cbmpc_paillier_encrypt(paillier, ptMem, &out)
	if rc != 0 {
		return nil, formatNativeErr("paillier_encrypt", rc)
	}
	return cmemToGoBytes(out), nil
}

// PaillierDecrypt decrypts a ciphertext value with the Paillier cryptosystem (requires private key).
func PaillierDecrypt(paillier Paillier, ciphertext []byte) ([]byte, error) {
	if paillier == nil {
		return nil, errors.New("nil paillier")
	}
	if len(ciphertext) == 0 {
		return nil, errors.New("empty ciphertext")
	}

	ctMem := goBytesToCmem(ciphertext)
	var out C.cmem_t
	rc := C.cbmpc_paillier_decrypt(paillier, ctMem, &out)
	if rc != 0 {
		return nil, formatNativeErr("paillier_decrypt", rc)
	}
	return cmemToGoBytes(out), nil
}

// PaillierAddCiphers adds two Paillier ciphertexts homomorphically.
func PaillierAddCiphers(paillier Paillier, c1, c2 []byte) ([]byte, error) {
	if paillier == nil {
		return nil, errors.New("nil paillier")
	}
	if len(c1) == 0 || len(c2) == 0 {
		return nil, errors.New("empty ciphertext")
	}

	c1Mem := goBytesToCmem(c1)
	c2Mem := goBytesToCmem(c2)
	var out C.cmem_t
	rc := C.cbmpc_paillier_add_ciphers(paillier, c1Mem, c2Mem, &out)
	if rc != 0 {
		return nil, formatNativeErr("paillier_add_ciphers", rc)
	}
	return cmemToGoBytes(out), nil
}

// PaillierMulScalar multiplies a Paillier ciphertext by a scalar homomorphically.
func PaillierMulScalar(paillier Paillier, ciphertext, scalar []byte) ([]byte, error) {
	if paillier == nil {
		return nil, errors.New("nil paillier")
	}
	if len(ciphertext) == 0 || len(scalar) == 0 {
		return nil, errors.New("empty ciphertext or scalar")
	}

	ctMem := goBytesToCmem(ciphertext)
	scMem := goBytesToCmem(scalar)
	var out C.cmem_t
	rc := C.cbmpc_paillier_mul_scalar(paillier, ctMem, scMem, &out)
	if rc != 0 {
		return nil, formatNativeErr("paillier_mul_scalar", rc)
	}
	return cmemToGoBytes(out), nil
}

// PaillierVerifyCipher verifies that a ciphertext is well-formed for this Paillier instance.
func PaillierVerifyCipher(paillier Paillier, ciphertext []byte) error {
	if paillier == nil {
		return errors.New("nil paillier")
	}
	if len(ciphertext) == 0 {
		return errors.New("empty ciphertext")
	}

	ctMem := goBytesToCmem(ciphertext)
	rc := C.cbmpc_paillier_verify_cipher(paillier, ctMem)
	if rc != 0 {
		return formatNativeErr("paillier_verify_cipher", rc)
	}
	return nil
}

// PaillierSerialize serializes a Paillier instance to bytes.
func PaillierSerialize(paillier Paillier) ([]byte, error) {
	if paillier == nil {
		return nil, errors.New("nil paillier")
	}

	var out C.cmem_t
	rc := C.cbmpc_paillier_serialize(paillier, &out)
	if rc != 0 {
		return nil, formatNativeErr("paillier_serialize", rc)
	}
	return cmemToGoBytes(out), nil
}

// PaillierDeserialize deserializes a Paillier instance from bytes.
// Returns a Paillier instance that must be freed with PaillierFree.
func PaillierDeserialize(data []byte) (Paillier, error) {
	if len(data) == 0 {
		return nil, errors.New("empty data")
	}

	dataMem := goBytesToCmem(data)
	var paillier Paillier
	rc := C.cbmpc_paillier_deserialize(dataMem, &paillier)
	if rc != 0 {
		return nil, formatNativeErr("paillier_deserialize", rc)
	}
	return paillier, nil
}
