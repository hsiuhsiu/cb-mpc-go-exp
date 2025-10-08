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

// Transport captures the messaging contract required by the native library. It
// must support both direct receive calls and batched ReceiveAll calls, even when
// only two parties are involved.
type Transport interface {
	Send(ctx context.Context, to RoleID, msg []byte) error
	Receive(ctx context.Context, from RoleID) ([]byte, error)
	ReceiveAll(ctx context.Context, from []RoleID) (map[RoleID][]byte, error)
}
