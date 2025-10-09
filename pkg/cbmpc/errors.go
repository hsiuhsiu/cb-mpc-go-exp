package cbmpc

import (
	"errors"
)

// ErrBitLeak indicates a signature verification failure in global abort mode,
// which may leak information about the private key. This error requires special
// handling - the key should be refreshed before signing again.
var ErrBitLeak = errors.New("bit leak detected in signature verification")

// remapError converts bindings layer errors to public API errors.
func remapError(err error) error {
	if err == nil {
		return nil
	}
	// Map bindings.ErrBitLeak to public ErrBitLeak
	if err.Error() == "bit leak detected in signature verification" {
		return ErrBitLeak
	}
	return err
}
