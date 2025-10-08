package cbmpc

// remapError is a pass-through for errors from the bindings layer.
// It exists to provide a hook for future error mapping if needed.
func remapError(err error) error {
	return err
}
