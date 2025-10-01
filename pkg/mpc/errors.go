package mpc

import (
	"errors"
	"fmt"
)

var (
	// ErrInvalidParameter indicates an invalid parameter was provided
	ErrInvalidParameter = errors.New("mpc: invalid parameter")

	// ErrNetworkFailure indicates a network communication error
	ErrNetworkFailure = errors.New("mpc: network failure")

	// ErrProtocolFailure indicates the MPC protocol failed
	ErrProtocolFailure = errors.New("mpc: protocol failure")

	// ErrInvalidSignature indicates signature verification failed
	ErrInvalidSignature = errors.New("mpc: invalid signature")

	// ErrInvalidKeyShare indicates the key share is invalid or corrupted
	ErrInvalidKeyShare = errors.New("mpc: invalid key share")

	// ErrSessionClosed indicates the session has been closed
	ErrSessionClosed = errors.New("mpc: session closed")
)

// Error wraps an underlying error with context
type Error struct {
	Op  string // Operation that failed
	Err error  // Underlying error
}

func (e *Error) Error() string {
	return fmt.Sprintf("mpc.%s: %v", e.Op, e.Err)
}

func (e *Error) Unwrap() error {
	return e.Err
}

// errorf creates a new Error
func errorf(op string, format string, args ...interface{}) error {
	return &Error{
		Op:  op,
		Err: fmt.Errorf(format, args...),
	}
}
