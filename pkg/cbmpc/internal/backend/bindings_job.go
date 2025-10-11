//go:build cgo && !windows

package backend

/*
#include <stdlib.h>
#include <string.h>
#include "capi.h"
#include "cbmpc/core/cmem.h"
*/
import "C"

import (
	"context"
	"errors"
	"runtime"
	"sync"
	"unsafe"
)

var (
	errJob2PNew = errors.New("job2p_new failed")
	errJobMPNew = errors.New("jobmp_new failed")
)

// transport defines the interface for sending and receiving messages between parties.
// Implementations must handle the underlying network communication and MUST be
// safe for concurrent use by multiple goroutines. Calls may originate from
// different OS threads via CGO callbacks.
//
// Context semantics: callbacks currently pass context.Background() because C++
// code drives the protocol and invokes these functions without a Go context.
// If your transport supports cancellation, consider providing a per-job
// cancellation mechanism and wiring it into this context in a future change.
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
//
// IMPORTANT: This returns unsafe.Pointer(uintptr(h)) which is explicitly allowed
// by CGO when the conversion happens in a single expression passed to a C function.
// See https://pkg.go.dev/cmd/cgo#hdr-Passing_pointers
func put(v any) (handle, uintptr) {
	mu.Lock()
	defer mu.Unlock()
	h := next
	next++
	reg[h] = v
	return h, uintptr(h)
}

// get retrieves a registered Go value from its handle pointer.
// The ptr is a void* from C that contains a handle value cast as a pointer.
func get(ptr unsafe.Pointer) (any, bool) {
	if ptr == nil {
		return nil, false
	}
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

// CGO export callbacks for the C library to call back into Go.
// These functions implement the transport layer that the C++ MPC library uses
// to send and receive messages between parties. They handle marshaling between
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
        data, ok := batch[role]
        if !ok {
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

// NewJob2P creates a new two-party MPC job.
//
// Parameters:
//   - t: The transport implementation for network communication
//   - self: The party ID (0 or 1)
//   - names: Array of exactly 2 party names
//
// Returns:
//   - unsafe.Pointer: The C job pointer (opaque)
//   - uintptr: The transport handle (needed for cleanup)
//   - error: Any error that occurred during creation
//
// The caller MUST call FreeJob2P when done to prevent memory leaks.
//
// Example:
//
//	job, handle, err := NewJob2P(transport, 0, []string{"party1", "party2"})
//	if err != nil {
//	    return err
//	}
//	defer FreeJob2P(job, handle)
//
//	// Use the job for protocol operations...
func NewJob2P(t transport, self uint32, names []string) (unsafe.Pointer, uintptr, error) {
	if t == nil {
		return nil, 0, errJob2PNew
	}
	if len(names) != 2 {
		return nil, 0, errJob2PNew
	}

	h, ctx := put(t)
	// Convert uintptr to unsafe.Pointer inline when passing to C.
	// This is explicitly allowed by CGO rules when done in the call expression.
	//nolint:govet // Intentional uintptr to unsafe.Pointer conversion for CGO
	goTransport := C.cbmpc_make_go_transport(unsafe.Pointer(ctx))

	cNames := make([]*C.char, len(names))
	for i, name := range names {
		cName := C.CString(name)
		cNames[i] = cName
		defer C.free(unsafe.Pointer(cName))
	}
	var namesPtr **C.char
	if len(cNames) > 0 {
		namesPtr = (**C.char)(unsafe.Pointer(&cNames[0]))
	}

	cj := C.cbmpc_job2p_new(&goTransport, C.uint32_t(self), namesPtr)
	if cj == nil {
		del(h)
		return nil, 0, errJob2PNew
	}

	runtime.KeepAlive(names)
	return unsafe.Pointer(cj), uintptr(h), nil
}

// FreeJob2P frees the resources associated with a two-party job.
//
// This function must be called for every successful NewJob2P call to:
//   - Free the C++ job object
//   - Remove the transport from the registry
//   - Prevent memory leaks
//
// Parameters:
//   - cjob: The job pointer returned by NewJob2P
//   - h: The handle returned by NewJob2P
//
// It is safe to call this function with nil/zero values.
func FreeJob2P(cjob unsafe.Pointer, h uintptr) {
	if cjob != nil {
		C.cbmpc_job2p_free((*C.cbmpc_job2p)(cjob))
	}
	if h != 0 {
		del(handle(h))
	}
}

// NewJobMP creates a new multi-party MPC job.
//
// Parameters:
//   - t: The transport implementation for network communication
//   - self: The party ID (0 to n-1)
//   - names: Array of party names (minimum 2 parties)
//
// Returns:
//   - unsafe.Pointer: The C job pointer (opaque)
//   - uintptr: The transport handle (needed for cleanup)
//   - error: Any error that occurred during creation
//
// The caller MUST call FreeJobMP when done to prevent memory leaks.
//
// Example:
//
//	job, handle, err := NewJobMP(transport, 0, []string{"party1", "party2", "party3"})
//	if err != nil {
//	    return err
//	}
//	defer FreeJobMP(job, handle)
//
//	// Use the job for protocol operations...
func NewJobMP(t transport, self uint32, names []string) (unsafe.Pointer, uintptr, error) {
	if t == nil {
		return nil, 0, errJobMPNew
	}
	if len(names) < 2 {
		return nil, 0, errJobMPNew
	}

	h, ctx := put(t)
	// Convert uintptr to unsafe.Pointer inline when passing to C.
	// This is explicitly allowed by CGO rules when done in the call expression.
	//nolint:govet // Intentional uintptr to unsafe.Pointer conversion for CGO
	goTransport := C.cbmpc_make_go_transport(unsafe.Pointer(ctx))

	cNames := make([]*C.char, len(names))
	for i, name := range names {
		cName := C.CString(name)
		cNames[i] = cName
		defer C.free(unsafe.Pointer(cName))
	}
	var namesPtr **C.char
	if len(cNames) > 0 {
		namesPtr = (**C.char)(unsafe.Pointer(&cNames[0]))
	}

	cj := C.cbmpc_jobmp_new(&goTransport, C.uint32_t(self), C.size_t(len(cNames)), namesPtr)
	if cj == nil {
		del(h)
		return nil, 0, errJobMPNew
	}

	runtime.KeepAlive(names)
	return unsafe.Pointer(cj), uintptr(h), nil
}

// FreeJobMP frees the resources associated with a multi-party job.
//
// This function must be called for every successful NewJobMP call to:
//   - Free the C++ job object
//   - Remove the transport from the registry
//   - Prevent memory leaks
//
// Parameters:
//   - cjob: The job pointer returned by NewJobMP
//   - h: The handle returned by NewJobMP
//
// It is safe to call this function with nil/zero values.
func FreeJobMP(cjob unsafe.Pointer, h uintptr) {
	if cjob != nil {
		C.cbmpc_jobmp_free((*C.cbmpc_jobmp)(cjob))
	}
	if h != 0 {
		del(handle(h))
	}
}
