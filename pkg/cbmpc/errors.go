package cbmpc

import (
	"errors"

	"github.com/coinbase/cb-mpc-go/internal/bindings"
)

var (
	// ErrNotBuilt reports that the Go bindings linked into this binary do not
	// contain the native cb-mpc implementation yet.
	ErrNotBuilt = errors.New("cbmpc: native bindings not built")

	// ErrCGONotEnabled reports that the package was compiled without cgo, so no
	// native library is available.
	ErrCGONotEnabled = errors.New("cbmpc: built without cgo support")

	// ErrLibraryClosed indicates that a call attempted to operate on a Library
	// that has already been closed.
	ErrLibraryClosed = errors.New("cbmpc: library already closed")
)

func remapError(err error) error {
	switch {
	case err == nil:
		return nil
	case errors.Is(err, bindings.ErrCGONotEnabled):
		return ErrCGONotEnabled
	case errors.Is(err, bindings.ErrNotBuilt):
		return ErrNotBuilt
	default:
		return err
	}
}
