//go:build cgo && !windows

package bindings

/*
#include <stdlib.h>
#include <string.h>
#include "cbmpc/core/cmem.h"
*/
import "C"

import (
	"unsafe"
)

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
