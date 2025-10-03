//go:build !cgo && !windows
// +build !cgo,!windows

package bindings

// Open is the non-cgo stub that reports the lack of native support.
func Open(Config) (Handle, error) {
	return 0, ErrCGONotEnabled
}

// Close reports the same cgo-disabled error.
func Close(Handle) error {
	return ErrCGONotEnabled
}

// Version returns an empty string when the native bindings are unavailable.
func Version() string { return "" }
