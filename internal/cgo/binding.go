// Package cgo provides the CGO bindings to the cb-mpc C++ library.
// This package should ONLY be imported by the pkg/mpc package.
// All CGO complexity is isolated here.
package cgo

/*
#cgo CXXFLAGS: -std=c++17 -Wno-switch -Wno-parentheses -Wno-attributes -Wno-deprecated-declarations -DNO_DEPRECATED_OPENSSL
#cgo CFLAGS: -Wno-deprecated-declarations
#cgo arm64 CXXFLAGS: -march=armv8-a+crypto
#cgo !linux LDFLAGS: -lcrypto
#cgo android LDFLAGS: -lcrypto -static-libstdc++
#cgo LDFLAGS: -ldl
#cgo darwin,!iossimulator,!ios CFLAGS: -I/usr/local/opt/openssl@3.2.0/include
#cgo darwin,!iossimulator,!ios CXXFLAGS: -I/usr/local/opt/openssl@3.2.0/include
#cgo darwin,!iossimulator,!ios LDFLAGS: -L/usr/local/opt/openssl@3.2.0/lib
#cgo linux,!android CFLAGS: -I/usr/local/include
#cgo linux,!android CXXFLAGS: -I/usr/local/include
#cgo linux,!android LDFLAGS: /usr/local/lib64/libcrypto.a

#cgo CFLAGS: -I${SRCDIR}
#cgo CXXFLAGS: -I${SRCDIR}
#cgo LDFLAGS: -lcbmpc

#include <stdlib.h>
#include <string.h>
#include "network.h"
#include "agree_random.h"
#include "ecdsa_2p.h"

extern int callback_send(void*, int, cmem_t);
extern int callback_receive(void*, int, cmem_t*);
extern int callback_receive_all(void*, int*, int, cmems_t*);

static void set_callbacks(data_transport_callbacks_t* dt_callbacks) {
	dt_callbacks->send_fun = callback_send;
	dt_callbacks->receive_fun = callback_receive;
	dt_callbacks->receive_all_fun = callback_receive_all;
}
*/
import "C"
import (
	"fmt"
	"sync"
	"unsafe"
)

// Error constants matching C++ error codes
const (
	Success      = 0
	Unknown      = 1
	ParamError   = 2
	MemoryError  = 3
	InvalidState = 4
)

// Session interface matches pkg/mpc.Session
type Session interface {
	Send(toParty int, msg []byte) error
	Receive(fromParty int) ([]byte, error)
	ReceiveAll(fromParties []int) ([][]byte, error)
	MyIndex() int
	PartyCount() int
}

// sessionMap stores Go Session instances keyed by unsafe.Pointer
var sessionMap sync.Map

func setSession(s Session) (unsafe.Pointer, error) {
	if s == nil {
		return nil, fmt.Errorf("session cannot be nil")
	}
	ptr := C.malloc(1)
	if ptr == nil {
		return nil, fmt.Errorf("failed to allocate session pointer")
	}
	sessionMap.Store(ptr, s)
	return ptr, nil
}

func freeSession(ptr unsafe.Pointer) error {
	if ptr == nil {
		return nil
	}
	_, loaded := sessionMap.LoadAndDelete(ptr)
	if !loaded {
		return fmt.Errorf("attempt to free unknown session pointer")
	}
	C.free(ptr)
	return nil
}

func getSession(ptr unsafe.Pointer) (Session, error) {
	if ptr == nil {
		return nil, fmt.Errorf("cannot get session from nil pointer")
	}
	s, ok := sessionMap.Load(ptr)
	if !ok {
		return nil, fmt.Errorf("failed to load session from pointer")
	}
	session, ok := s.(Session)
	if !ok {
		return nil, fmt.Errorf("stored value is not a Session")
	}
	return session, nil
}

// Callback functions - called from C++ back into Go

//export callback_send
func callback_send(ptr unsafe.Pointer, receiver C.int, message C.cmem_t) C.int {
	session, err := getSession(ptr)
	if err != nil {
		return C.int(-1)
	}

	var goBytes []byte
	if message.size > 0 && message.data != nil {
		goBytes = C.GoBytes(unsafe.Pointer(message.data), message.size)
	}

	if err := session.Send(int(receiver), goBytes); err != nil {
		return C.int(-1)
	}

	return C.int(0)
}

//export callback_receive
func callback_receive(ptr unsafe.Pointer, sender C.int, message *C.cmem_t) C.int {
	session, err := getSession(ptr)
	if err != nil {
		return C.int(-1)
	}

	received, err := session.Receive(int(sender))
	if err != nil {
		return C.int(-1)
	}

	message.size = C.int(len(received))
	if len(received) > 0 {
		buf := C.malloc(C.size_t(len(received)))
		if buf == nil {
			return C.int(-3) // NETWORK_MEMORY_ERROR
		}
		C.memcpy(buf, unsafe.Pointer(&received[0]), C.size_t(len(received)))
		message.data = (*C.uint8_t)(buf)
	} else {
		message.data = nil
	}

	return C.int(0)
}

//export callback_receive_all
func callback_receive_all(ptr unsafe.Pointer, senders *C.int, senderCount C.int, messages *C.cmems_t) C.int {
	session, err := getSession(ptr)
	if err != nil {
		return C.int(-1)
	}

	count := int(senderCount)
	if count == 0 {
		messages.count = 0
		messages.data = nil
		messages.sizes = nil
		return C.int(0)
	}

	// Convert C int array to Go slice
	sendersSlice := make([]int, count)
	cIntSize := int(unsafe.Sizeof(C.int(0)))
	for i := 0; i < count; i++ {
		ptr := (*C.int)(unsafe.Pointer(uintptr(unsafe.Pointer(senders)) + uintptr(i*cIntSize)))
		sendersSlice[i] = int(*ptr)
	}

	received, err := session.ReceiveAll(sendersSlice)
	if err != nil {
		return C.int(-1)
	}

	if len(received) != count {
		return C.int(-1)
	}

	// Calculate total size
	total := 0
	for i := 0; i < count; i++ {
		total += len(received[i])
	}

	// Allocate flattened data buffer
	var dataPtr unsafe.Pointer
	if total > 0 {
		dataPtr = C.malloc(C.size_t(total))
		if dataPtr == nil {
			return C.int(-3) // NETWORK_MEMORY_ERROR
		}
	}

	// Allocate sizes array
	sizesPtr := C.malloc(C.size_t(count) * C.size_t(cIntSize))
	if sizesPtr == nil && count > 0 {
		if dataPtr != nil {
			C.free(dataPtr)
		}
		return C.int(-3) // NETWORK_MEMORY_ERROR
	}

	// Copy data and sizes
	offset := 0
	for i := 0; i < count; i++ {
		// Set size
		sizePtr := (*C.int)(unsafe.Pointer(uintptr(sizesPtr) + uintptr(i*cIntSize)))
		*sizePtr = C.int(len(received[i]))

		// Copy data
		if len(received[i]) > 0 {
			C.memcpy(unsafe.Pointer(uintptr(dataPtr)+uintptr(offset)), unsafe.Pointer(&received[i][0]), C.size_t(len(received[i])))
			offset += len(received[i])
		}
	}

	messages.count = C.int(count)
	messages.data = (*C.uint8_t)(dataPtr)
	messages.sizes = (*C.int)(sizesPtr)

	return C.int(0)
}

// Memory utilities

func cmemToBytes(cmem C.cmem_t) []byte {
	if cmem.data == nil || cmem.size == 0 {
		return nil
	}
	out := C.GoBytes(unsafe.Pointer(cmem.data), cmem.size)
	// Zero and free the C memory
	C.memset(unsafe.Pointer(cmem.data), 0, C.ulong(cmem.size))
	C.free(unsafe.Pointer(cmem.data))
	return out
}

func bytesToCmem(data []byte) C.cmem_t {
	var mem C.cmem_t
	mem.size = C.int(len(data))
	if len(data) > 0 {
		mem.data = (*C.uchar)(&data[0])
	} else {
		mem.data = nil
	}
	return mem
}

// Helper to create C string arrays
func createCStringArray(strings []string) (unsafe.Pointer, []*C.char, error) {
	if len(strings) == 0 {
		return nil, nil, fmt.Errorf("string array cannot be empty")
	}

	cArray := C.malloc(C.size_t(len(strings)) * C.size_t(unsafe.Sizeof(uintptr(0))))
	if cArray == nil {
		return nil, nil, fmt.Errorf("failed to allocate memory for string array")
	}

	cSlice := (*[1 << 30]unsafe.Pointer)(cArray)[:len(strings):len(strings)]
	cStrs := make([]*C.char, len(strings))

	for i, str := range strings {
		if str == "" {
			C.free(cArray)
			for j := 0; j < i; j++ {
				C.free(unsafe.Pointer(cStrs[j]))
			}
			return nil, nil, fmt.Errorf("string at index %d cannot be empty", i)
		}
		cStrs[i] = C.CString(str)
		cSlice[i] = unsafe.Pointer(cStrs[i])
	}

	return cArray, cStrs, nil
}

func freeCStringArray(cArray unsafe.Pointer, cStrs []*C.char) {
	if cArray != nil {
		C.free(cArray)
	}
	for _, cStr := range cStrs {
		if cStr != nil {
			C.free(unsafe.Pointer(cStr))
		}
	}
}

var callbacks C.data_transport_callbacks_t

func init() {
	C.set_callbacks(&callbacks)
}
