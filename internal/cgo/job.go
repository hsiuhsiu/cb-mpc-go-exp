package cgo

// #include "network.h"
import "C"
import (
	"fmt"
	"unsafe"
)

// Job2P represents a two-party job
type Job2P struct {
	sessionPtr unsafe.Pointer
	cJob       *C.job_2p_ref
}

// NewJob2P creates a new two-party job
func NewJob2P(session Session, partyIndex int, partyNames []string) (*Job2P, error) {
	if len(partyNames) != 2 {
		return nil, fmt.Errorf("NewJob2P requires exactly 2 party names, got %d", len(partyNames))
	}

	if session == nil {
		return nil, fmt.Errorf("session cannot be nil")
	}

	if partyIndex < 0 || partyIndex > 1 {
		return nil, fmt.Errorf("party index must be 0 or 1, got %d", partyIndex)
	}

	ptr, err := setSession(session)
	if err != nil {
		return nil, fmt.Errorf("failed to set session: %w", err)
	}

	cArray, cStrs, err := createCStringArray(partyNames)
	if err != nil {
		freeSession(ptr)
		return nil, fmt.Errorf("failed to create C string array: %w", err)
	}
	defer freeCStringArray(cArray, cStrs)

	cJobRef := C.new_job_2p(&callbacks, ptr, C.int(partyIndex), (**C.char)(cArray), C.int(len(partyNames)))
	if cJobRef == nil {
		freeSession(ptr)
		return nil, fmt.Errorf("failed to create 2P job")
	}

	return &Job2P{
		sessionPtr: ptr,
		cJob:       cJobRef,
	}, nil
}

// Close releases resources
func (j *Job2P) Close() error {
	if j.cJob != nil {
		C.free_job_2p(j.cJob)
		j.cJob = nil
	}
	if j.sessionPtr != nil {
		freeSession(j.sessionPtr)
		j.sessionPtr = nil
	}
	return nil
}

// JobMP represents a multi-party job
type JobMP struct {
	sessionPtr unsafe.Pointer
	cJob       *C.job_mp_ref
}

// NewJobMP creates a new multi-party job
func NewJobMP(session Session, partyCount int, partyIndex int, partyNames []string) (*JobMP, error) {
	if len(partyNames) != partyCount {
		return nil, fmt.Errorf("NewJobMP requires pnames array length (%d) to match partyCount (%d)",
			len(partyNames), partyCount)
	}

	if session == nil {
		return nil, fmt.Errorf("session cannot be nil")
	}

	if partyCount <= 0 {
		return nil, fmt.Errorf("partyCount must be positive, got %d", partyCount)
	}

	if partyIndex < 0 || partyIndex >= partyCount {
		return nil, fmt.Errorf("partyIndex (%d) must be in range [0, %d)", partyIndex, partyCount)
	}

	ptr, err := setSession(session)
	if err != nil {
		return nil, fmt.Errorf("failed to set session: %w", err)
	}

	cArray, cStrs, err := createCStringArray(partyNames)
	if err != nil {
		freeSession(ptr)
		return nil, fmt.Errorf("failed to create C string array: %w", err)
	}
	defer freeCStringArray(cArray, cStrs)

	cJobRef := C.new_job_mp(&callbacks, ptr, C.int(partyCount), C.int(partyIndex), (**C.char)(cArray), C.int(len(partyNames)))
	if cJobRef == nil {
		freeSession(ptr)
		return nil, fmt.Errorf("failed to create MP job")
	}

	return &JobMP{
		sessionPtr: ptr,
		cJob:       cJobRef,
	}, nil
}

// Close releases resources
func (j *JobMP) Close() error {
	if j.cJob != nil {
		C.free_job_mp(j.cJob)
		j.cJob = nil
	}
	if j.sessionPtr != nil {
		freeSession(j.sessionPtr)
		j.sessionPtr = nil
	}
	return nil
}
