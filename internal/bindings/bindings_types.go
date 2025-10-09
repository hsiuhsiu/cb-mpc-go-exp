//go:build cgo && !windows

package bindings

/*
#include <stdlib.h>
#include <string.h>
#include "cbmpc/core/cmem.h"
*/
import "C"

import (
	"errors"
	"unsafe"
)

// Error codes from cb-mpc
const (
	E_ECDSA_2P_BIT_LEAK = 0xff040002 // Bit leak detected in signature verification
)

// ErrBitLeak is returned when E_ECDSA_2P_BIT_LEAK is detected
var ErrBitLeak = errors.New("bit leak detected in signature verification")

// cmemToGoBytes converts a C.cmem_t to a Go []byte slice and takes ownership of the C memory.
// Securely zeros and frees the C memory. Caller must not access the C memory after calling.
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
// The returned cmems_t points to allocated C memory that must be freed by the caller.
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
