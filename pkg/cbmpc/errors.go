package cbmpc

import (
	"errors"

	"github.com/coinbase/cb-mpc-go/pkg/cbmpc/internal/backend"
)

// ErrBitLeak indicates a signature verification failure in global abort mode,
// which may leak information about the private key. This error requires special
// handling - the key should be refreshed before signing again.
var ErrBitLeak = errors.New("bit leak detected in signature verification")

// RemapError converts bindings layer errors to public API errors.
// This is exported for use by protocol subpackages.
func RemapError(err error) error {
	if err == nil {
		return nil
	}
	// Map bindings.ErrBitLeak to public ErrBitLeak using errors.Is to avoid
	// string comparison fragility.
	if errors.Is(err, backend.ErrBitLeak) {
		return ErrBitLeak
	}
	return err
}
