//go:build !windows

package backend

import "errors"

// ErrNotBuilt reports that the native bindings were not linked into the
// current binary.
var ErrNotBuilt = errors.New("cbmpc/internal/bindings: native bindings not built")

// ErrBitLeak is returned when E_ECDSA_2P_BIT_LEAK is detected during
// signature verification with global abort. This indicates a potential
// key leak and the key should be considered compromised.
var ErrBitLeak = errors.New("bit leak detected in signature verification")

// Version returns the version string from the native library, or empty if not available.
func Version() string { return "" }
