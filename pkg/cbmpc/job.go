package cbmpc

import (
	"context"
	"errors"
	"fmt"
	"runtime"
	"unsafe"

	"github.com/coinbase/cb-mpc-go/pkg/cbmpc/internal/backend"
)

var (
	ErrInvalidBits  = errors.New("bitlen must be >= 8 and a multiple of 8")
	ErrBadPeers     = errors.New("invalid peers/self configuration")
	ErrNilTransport = errors.New("transport must not be nil")
	ErrJobClosed    = errors.New("job has been closed")
)

type Job2P struct {
	cptr   unsafe.Pointer
	hptr   uintptr
	cancel context.CancelFunc
}

type JobMP struct {
	cptr   unsafe.Pointer
	hptr   uintptr
	cancel context.CancelFunc
}

// transportAdapter bridges the public RoleID-based Transport interface with
// the uint32 identifiers required by the cgo bindings layer. The adapter keeps
// the exported API idiomatic while avoiding a dependency cycle between pkg and
// internal/bindings.
type transportAdapter struct {
	inner Transport
	ctx   context.Context
}

func (a transportAdapter) Send(_ context.Context, to uint32, msg []byte) error {
	return a.inner.Send(a.ctx, RoleID(to), msg)
}

func (a transportAdapter) Receive(_ context.Context, from uint32) ([]byte, error) {
	return a.inner.Receive(a.ctx, RoleID(from))
}

func (a transportAdapter) ReceiveAll(_ context.Context, from []uint32) (map[uint32][]byte, error) {
	roles := make([]RoleID, len(from))
	for i, r := range from {
		roles[i] = RoleID(r)
	}
	batch, err := a.inner.ReceiveAll(a.ctx, roles)
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
// This variant uses a background context; see NewJob2PWithContext to provide
// a cancellable context for transport operations.
func NewJob2P(t Transport, self Role, names [2]string) (*Job2P, error) {
	return NewJob2PWithContext(context.Background(), t, self, names)
}

// NewJob2PWithContext constructs a 2-party job with a parent context. A child
// context derived from ctx is used for all transport operations and will be
// canceled during Close() to promptly unblock pending receives.
func NewJob2PWithContext(ctx context.Context, t Transport, self Role, names [2]string) (*Job2P, error) {
	if t == nil {
		return nil, ErrNilTransport
	}
	if !self.valid() {
		return nil, fmt.Errorf("%w: role %d is not valid", ErrBadPeers, self)
	}
	if names[0] == "" || names[1] == "" {
		return nil, fmt.Errorf("%w: party names must not be empty", ErrBadPeers)
	}
	if names[0] == names[1] {
		return nil, fmt.Errorf("%w: party names must be unique (got %q)", ErrBadPeers, names[0])
	}

	jobCtx, cancel := context.WithCancel(ctx)
	adapter := transportAdapter{inner: t, ctx: jobCtx}
	cjob, h, err := backend.NewJob2P(adapter, uint32(self.roleID()), []string{names[0], names[1]})
	if err != nil {
		cancel()
		return nil, RemapError(err)
	}

	j := &Job2P{cptr: cjob, hptr: h, cancel: cancel}
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
	if j.cancel != nil {
		j.cancel()
	}
	backend.FreeJob2P(j.cptr, j.hptr)
	j.cptr = nil
	j.hptr = 0
	j.cancel = nil
	return nil
}

// NewJobMP constructs an n-party job. Each entry in names identifies a party in
// the session; self is the caller's index within that slice.
// This variant uses a background context; see NewJobMPWithContext to provide
// a cancellable context for transport operations.
func NewJobMP(t Transport, self RoleID, names []string) (*JobMP, error) {
	return NewJobMPWithContext(context.Background(), t, self, names)
}

// NewJobMPWithContext constructs an n-party job with a parent context. A child
// context derived from ctx is used for all transport operations and will be
// canceled during Close() to promptly unblock pending receives.
func NewJobMPWithContext(ctx context.Context, t Transport, self RoleID, names []string) (*JobMP, error) {
	if t == nil {
		return nil, ErrNilTransport
	}
	n := len(names)
	if n < 2 {
		return nil, fmt.Errorf("%w: need at least 2 parties (got %d)", ErrBadPeers, n)
	}
	if int(self) < 0 || int(self) >= n {
		return nil, fmt.Errorf("%w: self role %d out of range [0,%d)", ErrBadPeers, self, n)
	}

	seen := make(map[string]struct{}, n)
	for i, name := range names {
		if name == "" {
			return nil, fmt.Errorf("%w: party name at index %d is empty", ErrBadPeers, i)
		}
		if _, dup := seen[name]; dup {
			return nil, fmt.Errorf("%w: duplicate party name %q", ErrBadPeers, name)
		}
		seen[name] = struct{}{}
	}

	jobCtx, cancel := context.WithCancel(ctx)
	adapter := transportAdapter{inner: t, ctx: jobCtx}
	cjob, h, err := backend.NewJobMP(adapter, uint32(self), names)
	if err != nil {
		cancel()
		return nil, RemapError(err)
	}

	j := &JobMP{cptr: cjob, hptr: h, cancel: cancel}
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
	if j.cancel != nil {
		j.cancel()
	}
	backend.FreeJobMP(j.cptr, j.hptr)
	j.cptr = nil
	j.hptr = 0
	j.cancel = nil
	return nil
}

// Ptr returns the unsafe pointer to the underlying C job.
// This is exported for use by protocol subpackages.
func (j *Job2P) Ptr() (unsafe.Pointer, error) {
	if j == nil || j.cptr == nil {
		return nil, ErrJobClosed
	}
	return j.cptr, nil
}

// Ptr returns the unsafe pointer to the underlying C job.
// This is exported for use by protocol subpackages.
func (j *JobMP) Ptr() (unsafe.Pointer, error) {
	if j == nil || j.cptr == nil {
		return nil, ErrJobClosed
	}
	return j.cptr, nil
}

// SessionID represents a session identifier for MPC protocols.
type SessionID []byte

// Clone creates a defensive copy of the SessionID.
// This prevents external mutation of the session ID data.
//
// Returns a new SessionID with copied data. If the SessionID is nil or empty,
// returns nil to preserve the "fresh session" semantics.
func (s SessionID) Clone() SessionID {
	if len(s) == 0 {
		return nil
	}
	clone := make(SessionID, len(s))
	copy(clone, s)
	return clone
}

// IsEmpty returns true if the SessionID is empty (nil or zero-length).
// An empty SessionID indicates a fresh session should be created.
func (s SessionID) IsEmpty() bool {
	return len(s) == 0
}
