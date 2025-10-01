package cgo

// #include "agree_random.h"
import "C"
import "fmt"

// AgreeRandom executes the two-party agree random protocol
// Both parties will agree on the same random value of bitLen bits
func AgreeRandom(job *Job2P, bitLen int) ([]byte, error) {
	if job == nil || job.cJob == nil {
		return nil, fmt.Errorf("job is nil or not initialized")
	}

	if bitLen <= 0 {
		return nil, fmt.Errorf("bitLen must be positive, got %d", bitLen)
	}

	var out C.cmem_t
	cErr := C.mpc_agree_random(job.cJob, C.int(bitLen), &out)
	if cErr != C.int(Success) {
		return nil, fmt.Errorf("mpc_agree_random failed with error code %d", cErr)
	}

	return cmemToBytes(out), nil
}

// MultiAgreeRandom executes the multi-party agree random protocol
// All parties will agree on the same random value of bitLen bits
func MultiAgreeRandom(job *JobMP, bitLen int) ([]byte, error) {
	if job == nil || job.cJob == nil {
		return nil, fmt.Errorf("job is nil or not initialized")
	}

	if bitLen <= 0 {
		return nil, fmt.Errorf("bitLen must be positive, got %d", bitLen)
	}

	var out C.cmem_t
	cErr := C.mpc_multi_agree_random(job.cJob, C.int(bitLen), &out)
	if cErr != C.int(Success) {
		return nil, fmt.Errorf("mpc_multi_agree_random failed with error code %d", cErr)
	}

	return cmemToBytes(out), nil
}
