//go:build !windows

package bindings

import "errors"

var (
	// ErrNotBuilt reports that the native bindings were not linked into the
	// current binary.
	ErrNotBuilt = errors.New("cbmpc/internal/bindings: native bindings not built")
)

// Version returns the version string from the native library, or empty if not available.
func Version() string { return "" }
