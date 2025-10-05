package cbmpc

import (
	"context"
	"errors"
	"runtime"
	"unsafe"

	"github.com/coinbase/cb-mpc-go/internal/bindings"
)

var (
	ErrInvalidBits = errors.New("bitlen must be >= 8 and a multiple of 8")
	ErrBadPeers    = errors.New("invalid peers/self set")

	errNilTransport = errors.New("cbmpc: nil transport")
	errJobClosed    = errors.New("cbmpc: job closed")
)

type Job2P struct {
	cptr unsafe.Pointer
	hptr uintptr
}

type JobMP struct {
	cptr unsafe.Pointer
	hptr uintptr
}

// transportAdapter bridges the public RoleID-based Transport interface with
// the uint32 identifiers required by the cgo bindings layer. The adapter keeps
// the exported API idiomatic while avoiding a dependency cycle between pkg and
// internal/bindings.
type transportAdapter struct {
	inner Transport
}

func (a transportAdapter) Send(ctx context.Context, to uint32, msg []byte) error {
	return a.inner.Send(ctx, RoleID(to), msg)
}

func (a transportAdapter) Receive(ctx context.Context, from uint32) ([]byte, error) {
	return a.inner.Receive(ctx, RoleID(from))
}

func (a transportAdapter) ReceiveAll(ctx context.Context, from []uint32) (map[uint32][]byte, error) {
	roles := make([]RoleID, len(from))
	for i, r := range from {
		roles[i] = RoleID(r)
	}
	batch, err := a.inner.ReceiveAll(ctx, roles)
	if err != nil {
		return nil, err
	}
	out := make(map[uint32][]byte, len(batch))
	for role, data := range batch {
		out[uint32(role)] = data
	}
	return out, nil
}

// NewJob2P constructs a 2-party job using the provided transport, role, and
// party names. Names must be stable, unique identifiers for each participant.
func NewJob2P(t Transport, self Role, names [2]string) (*Job2P, error) {
	if t == nil {
		return nil, errNilTransport
	}
	if !self.valid() {
		return nil, ErrBadPeers
	}
	if names[0] == "" || names[1] == "" || names[0] == names[1] {
		return nil, ErrBadPeers
	}

	adapter := transportAdapter{inner: t}
	cjob, h, err := bindings.NewJob2P(adapter, uint32(self.roleID()), []string{names[0], names[1]})
	if err != nil {
		return nil, remapError(err)
	}

	j := &Job2P{cptr: cjob, hptr: h}
	runtime.SetFinalizer(j, func(j *Job2P) { _ = j.Close() })
	return j, nil
}

func (j *Job2P) Close() error {
	if j == nil {
		return nil
	}
	if j.cptr == nil && j.hptr == 0 {
		return nil
	}

	runtime.SetFinalizer(j, nil)
	bindings.FreeJob2P(j.cptr, j.hptr)
	j.cptr = nil
	j.hptr = 0
	return nil
}

// NewJobMP constructs an n-party job. Each entry in names identifies a party in
// the session; self is the caller's index within that slice.
func NewJobMP(t Transport, self RoleID, names []string) (*JobMP, error) {
	if t == nil {
		return nil, errNilTransport
	}
	n := len(names)
	if n < 2 {
		return nil, ErrBadPeers
	}
	if int(self) < 0 || int(self) >= n {
		return nil, ErrBadPeers
	}

	seen := make(map[string]struct{}, n)
	for _, name := range names {
		if name == "" {
			return nil, ErrBadPeers
		}
		if _, dup := seen[name]; dup {
			return nil, ErrBadPeers
		}
		seen[name] = struct{}{}
	}

	adapter := transportAdapter{inner: t}
	cjob, h, err := bindings.NewJobMP(adapter, uint32(self), names)
	if err != nil {
		return nil, remapError(err)
	}

	j := &JobMP{cptr: cjob, hptr: h}
	runtime.SetFinalizer(j, func(j *JobMP) { _ = j.Close() })
	return j, nil
}

func (j *JobMP) Close() error {
	if j == nil {
		return nil
	}
	if j.cptr == nil && j.hptr == 0 {
		return nil
	}

	runtime.SetFinalizer(j, nil)
	bindings.FreeJobMP(j.cptr, j.hptr)
	j.cptr = nil
	j.hptr = 0
	return nil
}

func (j *Job2P) ptr() (unsafe.Pointer, error) {
	if j == nil || j.cptr == nil {
		return nil, errJobClosed
	}
	return j.cptr, nil
}

func (j *JobMP) ptr() (unsafe.Pointer, error) {
	if j == nil || j.cptr == nil {
		return nil, errJobClosed
	}
	return j.cptr, nil
}
