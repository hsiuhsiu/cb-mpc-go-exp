//go:build cgo && !windows

package bindings

/*
#include "capi.h"
#include "cbmpc/core/cmem.h"
*/
import "C"

import (
	"errors"
	"unsafe"
)

// AgreeRandom2P executes the two-party agree random protocol.
//
// This protocol allows two parties to jointly generate a random value that neither
// party can predict or bias. The output is the same for both parties.
//
// Parameters:
//   - cj: The two-party job created with NewJob2P
//   - bitlen: The number of random bits to generate
//
// Returns:
//   - []byte: The random bytes (length = ceil(bitlen/8))
//   - error: Any error that occurred during the protocol
//
// The protocol performs network communication and may take time to complete.
// Both parties must call this function with the same bitlen parameter.
//
// Example:
//
//	job, handle, _ := NewJob2P(transport, 0, []string{"p1", "p2"})
//	defer FreeJob2P(job, handle)
//
//	randomBytes, err := AgreeRandom2P(job, 256)  // Generate 256 bits
//	if err != nil {
//	    return err
//	}
//	// Both parties now have the same 32 bytes of random data
func AgreeRandom2P(cj unsafe.Pointer, bitlen int) ([]byte, error) {
	if cj == nil {
		return nil, errors.New("nil job")
	}
	var out C.cmem_t
	rc := C.cbmpc_agree_random_2p((*C.cbmpc_job2p)(cj), C.int(bitlen), &out)
	if rc != 0 {
		return nil, errors.New("agree_random failed")
	}
	return cmemToGoBytes(out), nil
}

// AgreeRandomMP executes the multi-party agree random protocol.
//
// This protocol allows multiple parties (3+) to jointly generate a random value that
// no party can predict or bias. The output is the same for all parties.
//
// Parameters:
//   - cj: The multi-party job created with NewJobMP
//   - bitlen: The number of random bits to generate
//
// Returns:
//   - []byte: The random bytes (length = ceil(bitlen/8))
//   - error: Any error that occurred during the protocol
//
// The protocol performs network communication and may take time to complete.
// All parties must call this function with the same bitlen parameter.
//
// Example:
//
//	job, handle, _ := NewJobMP(transport, 0, []string{"p1", "p2", "p3"})
//	defer FreeJobMP(job, handle)
//
//	randomBytes, err := AgreeRandomMP(job, 256)  // Generate 256 bits
//	if err != nil {
//	    return err
//	}
//	// All parties now have the same 32 bytes of random data
func AgreeRandomMP(cj unsafe.Pointer, bitlen int) ([]byte, error) {
	if cj == nil {
		return nil, errors.New("nil job")
	}
	var out C.cmem_t
	rc := C.cbmpc_multi_agree_random((*C.cbmpc_jobmp)(cj), C.int(bitlen), &out)
	if rc != 0 {
		return nil, errors.New("multi_agree_random failed")
	}
	return cmemToGoBytes(out), nil
}
