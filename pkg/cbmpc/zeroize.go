package cbmpc

import "runtime"

// ZeroizeBytes overwrites the provided slice with zeros and prevents compiler
// dead store elimination using runtime.KeepAlive.
//
// This follows the pattern recommended in golang/go#33325 and used by security-
// focused libraries. While this cannot guarantee complete memory sanitization
// due to Go's garbage collector and potential copies made by crypto libraries,
// it represents current best practice in the Go ecosystem for sensitive memory.
//
// The underlying cb-mpc C++ library also performs its own secure zeroization
// of internal buffers using OpenSSL's OPENSSL_cleanse or platform-specific APIs.
func ZeroizeBytes(buf []byte) {
	for i := range buf {
		buf[i] = 0
	}
	// Prevent dead store elimination per golang/go#33325
	runtime.KeepAlive(buf)
}
