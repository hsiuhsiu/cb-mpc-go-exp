//go:build cgo && !windows

package bindings

// Open compiles in cgo-enabled builds but still reports that the native
// bindings are not yet wired in. The cgo-backed version will replace this file
// once the integration lands.
func Open(Config) (Handle, error) {
	return 0, ErrNotBuilt
}

// Close mirrors Open for symmetry in cgo-enabled builds.
func Close(Handle) error {
	return ErrNotBuilt
}

// Version returns an empty string until the real bindings are implemented.
func Version() string { return "" }
