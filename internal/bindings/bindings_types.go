//go:build cgo && !windows

package bindings

/*
#include <stdlib.h>
#include <string.h>
#include "cbmpc/core/cmem.h"
*/
import "C"

import (
	"context"
	"sync"
	"unsafe"
)

// transport defines the interface for sending and receiving messages between parties.
// Implementations must handle the underlying network communication.
type transport interface {
	Send(context.Context, uint32, []byte) error
	Receive(context.Context, uint32) ([]byte, error)
	ReceiveAll(context.Context, []uint32) (map[uint32][]byte, error)
}

// handle is an opaque reference to a registered Go object that can be passed to C code.
type handle uintptr

var (
	mu   sync.Mutex
	next handle = 1
	reg         = map[handle]any{}
)

// put registers a Go value and returns a handle that can be passed to C code.
// The handle must be freed with del() when no longer needed.
func put(v any) (handle, unsafe.Pointer) {
	mu.Lock()
	h := next
	next++
	reg[h] = v
	mu.Unlock()
	return h, unsafe.Pointer(uintptr(h))
}

// get retrieves a registered Go value from its handle.
func get(ptr unsafe.Pointer) (any, bool) {
	h := handle(uintptr(ptr))
	mu.Lock()
	v, ok := reg[h]
	mu.Unlock()
	return v, ok
}

// del removes a registered Go value from the registry.
func del(h handle) {
	mu.Lock()
	delete(reg, h)
	mu.Unlock()
}

// cmemToGoBytes converts a C.cmem_t to a Go []byte slice and takes ownership of the C memory.
// It checks if the data pointer is nil before conversion, copies the data to Go memory,
// securely zeros the C memory, and then frees it.
//
// This function is used to safely transfer data from C to Go while ensuring that sensitive
// data in C memory is properly cleaned up.
//
// The caller must not access or free the C memory after calling this function.
func cmemToGoBytes(cmem C.cmem_t) []byte {
	if cmem.data == nil || cmem.size <= 0 {
		return nil
	}

	// Copy C memory to Go memory
	result := C.GoBytes(unsafe.Pointer(cmem.data), cmem.size)

	// Securely zero and free the C memory
	if cmem.size > 0 {
		C.memset(unsafe.Pointer(cmem.data), 0, C.size_t(cmem.size))
	}
	C.free(unsafe.Pointer(cmem.data))

	return result
}

// CGO export callbacks for the C library to call back into Go.
// These functions implement the transport layer that the C++ MPC library uses
// to send and receive messages between parties. They handle marshalling between
// Go and C types.

//export cbmpc_go_send
func cbmpc_go_send(ctx unsafe.Pointer, to C.uint32_t, ptr *C.uint8_t, n C.size_t) C.int {
	v, ok := get(ctx)
	if !ok {
		return 1
	}
	t, ok := v.(transport)
	if !ok {
		return 1
	}
	msg := C.GoBytes(unsafe.Pointer(ptr), C.int(n))
	if err := t.Send(context.Background(), uint32(to), msg); err != nil {
		return 1
	}
	return 0
}

//export cbmpc_go_receive
func cbmpc_go_receive(ctx unsafe.Pointer, from C.uint32_t, out *C.cmem_t) C.int {
	v, ok := get(ctx)
	if !ok {
		return 1
	}
	t, ok := v.(transport)
	if !ok {
		return 1
	}
	msg, err := t.Receive(context.Background(), uint32(from))
	if err != nil {
		return 1
	}
	var p *C.uint8_t
	if len(msg) > 0 {
		p = (*C.uint8_t)(C.malloc(C.size_t(len(msg))))
		if p == nil {
			return 1
		}
		C.memcpy(unsafe.Pointer(p), unsafe.Pointer(&msg[0]), C.size_t(len(msg)))
	}
	out.data = p
	out.size = C.int(len(msg))
	return 0
}

//export cbmpc_go_receive_all
func cbmpc_go_receive_all(ctx unsafe.Pointer, from *C.uint32_t, n C.size_t, outs *C.cmem_t) C.int {
	v, ok := get(ctx)
	if !ok {
		return 1
	}
	t, ok := v.(transport)
	if !ok {
		return 1
	}
	count := int(n)
	roles := make([]uint32, count)
	src := unsafe.Slice(from, count)
	for i := range roles {
		roles[i] = uint32(src[i])
	}
	batch, err := t.ReceiveAll(context.Background(), roles)
	if err != nil {
		return 1
	}
	dst := unsafe.Slice(outs, count)
	for i, role := range roles {
		data := batch[role]
		var p *C.uint8_t
		if len(data) > 0 {
			p = (*C.uint8_t)(C.malloc(C.size_t(len(data))))
			if p == nil {
				// Cleanup already allocated memory on failure
				for j := 0; j < i; j++ {
					if dst[j].data != nil {
						C.memset(unsafe.Pointer(dst[j].data), 0, C.size_t(dst[j].size))
						C.free(unsafe.Pointer(dst[j].data))
					}
					dst[j].data = nil
					dst[j].size = 0
				}
				return 1
			}
			C.memcpy(unsafe.Pointer(p), unsafe.Pointer(&data[0]), C.size_t(len(data)))
		}
		dst[i].data = p
		dst[i].size = C.int(len(data))
	}
	return 0
}
