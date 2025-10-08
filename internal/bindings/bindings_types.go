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
