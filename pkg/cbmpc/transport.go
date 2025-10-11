package cbmpc

import "context"

// RoleID identifies the caller's role within a job. Values start at 0 and
// increase monotonically for additional parties.
type RoleID uint32

// Role enumerates the fixed two-party positions supported by job_2p_t.
type Role uint8

const (
	RoleP1 Role = iota
	RoleP2
)

func (r Role) roleID() RoleID { return RoleID(r) }

func (r Role) valid() bool { return r == RoleP1 || r == RoleP2 }

func (r Role) peer() RoleID {
	if r == RoleP1 {
		return RoleID(RoleP2)
	}
	return RoleID(RoleP1)
}

// Transport captures the messaging contract required by the native library.
//
// Concurrency: Implementations MUST be safe for concurrent use by multiple
// goroutines. The native code may invoke send/receive callbacks from different
// OS threads via CGO.
//
// Cancellation: The native code currently drives the protocol and callbacks do
// not carry a caller-provided context. Implementations may treat ctx as a best-
// effort cancellation signal (e.g., per-session context) if available. Future
// versions may add explicit cancellation plumbing per job.
//
// Semantics: Transport must support both direct Receive and batched ReceiveAll
// calls, even in two-party settings. For ReceiveAll, the returned map MUST
// contain exactly one entry per requested role; missing entries are treated as
// an error in the bindings layer.
type Transport interface {
	Send(ctx context.Context, to RoleID, msg []byte) error
	Receive(ctx context.Context, from RoleID) ([]byte, error)
	ReceiveAll(ctx context.Context, from []RoleID) (map[RoleID][]byte, error)
}
