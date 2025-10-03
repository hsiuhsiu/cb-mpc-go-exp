package cbmpc

// ZeroizeBytes overwrites the provided slice with zeros. It is a best-effort
// helper that keeps sensitive buffers from hanging around in heap snapshots
// while we work towards a proper native implementation.
func ZeroizeBytes(buf []byte) {
	for i := range buf {
		buf[i] = 0
	}
}

// ZeroizeString overwrites the contents of the provided string by copying it
// into a mutable byte slice before zeroing. The helper is intentionally naive
// but good enough for placeholder logic.
func ZeroizeString(s *string) {
	if s == nil {
		return
	}

	bytes := []byte(*s)
	ZeroizeBytes(bytes)
	*s = string(bytes)
}
