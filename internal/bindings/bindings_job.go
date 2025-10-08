//go:build cgo && !windows

package bindings

/*
#include <stdlib.h>
#include "capi.h"
*/
import "C"

import (
	"errors"
	"runtime"
	"unsafe"
)

var (
	errJob2PNew = errors.New("job2p_new failed")
	errJobMPNew = errors.New("jobmp_new failed")
)

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
	goTransport := C.cbmpc_make_go_transport(ctx)

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
	goTransport := C.cbmpc_make_go_transport(ctx)

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
