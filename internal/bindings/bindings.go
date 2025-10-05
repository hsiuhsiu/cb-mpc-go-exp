//go:build cgo && !windows

package bindings

/*
#cgo CFLAGS: -I${SRCDIR}/../../cb-mpc/src -I${SRCDIR}/../../cb-mpc/src/cbmpc -I${SRCDIR}/../../build/openssl-host/include -I${SRCDIR}/../../build/openssl-docker/include -Wno-parentheses
#cgo CXXFLAGS: -std=c++17 -I${SRCDIR}/../../cb-mpc/src -I${SRCDIR}/../../cb-mpc/src/cbmpc -I${SRCDIR}/../../build/openssl-host/include -I${SRCDIR}/../../build/openssl-docker/include -Wno-parentheses
#cgo LDFLAGS: -L${SRCDIR}/../../cb-mpc/lib/Release -L${SRCDIR}/../../build/openssl-host/lib -L${SRCDIR}/../../build/openssl-host/lib64 -L${SRCDIR}/../../build/openssl-docker/lib -L${SRCDIR}/../../build/openssl-docker/lib64 -lcbmpc -lssl -lcrypto -ldl
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

type transport interface {
	Send(context.Context, uint32, []byte) error
	Receive(context.Context, uint32) ([]byte, error)
	ReceiveAll(context.Context, []uint32) (map[uint32][]byte, error)
}

type handle uintptr

var (
	mu   sync.Mutex
	next handle = 1
	reg         = map[handle]any{}
)

func put(v any) (handle, unsafe.Pointer) {
	mu.Lock()
	h := next
	next++
	reg[h] = v
	mu.Unlock()
	return h, unsafe.Pointer(uintptr(h))
}

func get(ptr unsafe.Pointer) (any, bool) {
	h := handle(uintptr(ptr))
	mu.Lock()
	v, ok := reg[h]
	mu.Unlock()
	return v, ok
}

func del(h handle) {
	mu.Lock()
	delete(reg, h)
	mu.Unlock()
}

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

var (
	errJob2PNew = errors.New("job2p_new failed")
	errJobMPNew = errors.New("jobmp_new failed")
)

func NewJob2P(t transport, self uint32, names []string) (unsafe.Pointer, uintptr, error) {
	if t == nil {
		return nil, 0, errJob2PNew
	}
	h, ctx := put(t)
	goTransport := C.cbmpc_make_go_transport(ctx)
	if len(names) != 2 {
		del(h)
		return nil, 0, errJob2PNew
	}
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

func FreeJob2P(cjob unsafe.Pointer, h uintptr) {
	if cjob != nil {
		C.cbmpc_job2p_free((*C.cbmpc_job2p)(cjob))
	}
	if h != 0 {
		del(handle(h))
	}
}

func NewJobMP(t transport, self uint32, names []string) (unsafe.Pointer, uintptr, error) {
	if t == nil {
		return nil, 0, errJobMPNew
	}
	h, ctx := put(t)
	goTransport := C.cbmpc_make_go_transport(ctx)

	if len(names) < 2 {
		del(h)
		return nil, 0, errJobMPNew
	}
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

func FreeJobMP(cjob unsafe.Pointer, h uintptr) {
	if cjob != nil {
		C.cbmpc_jobmp_free((*C.cbmpc_jobmp)(cjob))
	}
	if h != 0 {
		del(handle(h))
	}
}

func AgreeRandom2P(cj unsafe.Pointer, bitlen int) ([]byte, error) {
	if cj == nil {
		return nil, errors.New("nil job")
	}
	var out C.cmem_t
	rc := C.cbmpc_agree_random_2p((*C.cbmpc_job2p)(cj), C.int(bitlen), &out)
	if rc != 0 {
		return nil, errors.New("agree_random failed")
	}
	var res []byte
	if out.size > 0 {
		res = C.GoBytes(unsafe.Pointer(out.data), out.size)
	}
	C.cbmpc_last_call_scratch_free()
	return res, nil
}

func AgreeRandomMP(cj unsafe.Pointer, bitlen int) ([]byte, error) {
	if cj == nil {
		return nil, errors.New("nil job")
	}
	var out C.cmem_t
	rc := C.cbmpc_multi_agree_random((*C.cbmpc_jobmp)(cj), C.int(bitlen), &out)
	if rc != 0 {
		return nil, errors.New("multi_agree_random failed")
	}
	var res []byte
	if out.size > 0 {
		res = C.GoBytes(unsafe.Pointer(out.data), out.size)
	}
	C.cbmpc_last_call_scratch_free()
	return res, nil
}
