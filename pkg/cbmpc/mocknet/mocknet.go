package mocknet

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"sync"

	"github.com/coinbase/cb-mpc-go/pkg/cbmpc"
)

type Net struct {
	mu sync.Mutex
	q  map[queueKey]chan []byte
}

func New() *Net { return &Net{q: make(map[queueKey]chan []byte)} }

type queueKey struct {
	from cbmpc.RoleID
	to   cbmpc.RoleID
	seq  uint64
}

type endpointCore struct {
	net  *Net
	self cbmpc.RoleID

	mu        sync.Mutex
	sendSeq   map[cbmpc.RoleID]uint64
	recvSeq   map[cbmpc.RoleID]uint64
	sendLocks map[cbmpc.RoleID]*sync.Mutex
	recvLocks map[cbmpc.RoleID]*sync.Mutex
}

func newEndpointCore(n *Net, self cbmpc.RoleID) *endpointCore {
	return &endpointCore{
		net:       n,
		self:      self,
		sendSeq:   make(map[cbmpc.RoleID]uint64),
		recvSeq:   make(map[cbmpc.RoleID]uint64),
		sendLocks: make(map[cbmpc.RoleID]*sync.Mutex),
		recvLocks: make(map[cbmpc.RoleID]*sync.Mutex),
	}
}

func (c *endpointCore) key(from, to cbmpc.RoleID, seq uint64) queueKey {
	return queueKey{from: from, to: to, seq: seq}
}

func (c *endpointCore) sendLock(role cbmpc.RoleID) *sync.Mutex {
	c.mu.Lock()
	defer c.mu.Unlock()
	lock := c.sendLocks[role]
	if lock == nil {
		lock = &sync.Mutex{}
		c.sendLocks[role] = lock
	}
	return lock
}

func (c *endpointCore) recvLock(role cbmpc.RoleID) *sync.Mutex {
	c.mu.Lock()
	defer c.mu.Unlock()
	lock := c.recvLocks[role]
	if lock == nil {
		lock = &sync.Mutex{}
		c.recvLocks[role] = lock
	}
	return lock
}

func (c *endpointCore) currentSendSeq(role cbmpc.RoleID) uint64 {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.sendSeq[role]
}

func (c *endpointCore) advanceSendSeq(role cbmpc.RoleID) {
	c.mu.Lock()
	c.sendSeq[role]++
	c.mu.Unlock()
}

func (c *endpointCore) currentRecvSeq(role cbmpc.RoleID) uint64 {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.recvSeq[role]
}

func (c *endpointCore) advanceRecvSeq(role cbmpc.RoleID) {
	c.mu.Lock()
	c.recvSeq[role]++
	c.mu.Unlock()
}

func (n *Net) slot(key queueKey) chan []byte {
	n.mu.Lock()
	defer n.mu.Unlock()
	ch := n.q[key]
	if ch == nil {
		ch = make(chan []byte, 1)
		n.q[key] = ch
	}
	return ch
}

func (n *Net) deliver(ctx context.Context, key queueKey, payload []byte) error {
	ch := n.slot(key)
	msg := append([]byte(nil), payload...)
	select {
	case ch <- msg:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (n *Net) await(ctx context.Context, key queueKey) ([]byte, error) {
	ch := n.slot(key)
	select {
	case msg := <-ch:
		n.mu.Lock()
		delete(n.q, key)
		n.mu.Unlock()
		return msg, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

type endpoint struct {
	core  *endpointCore
	peers map[cbmpc.RoleID]struct{}
}

func newEndpoint(n *Net, self cbmpc.RoleID, peers []cbmpc.RoleID) *endpoint {
	peerSet := make(map[cbmpc.RoleID]struct{}, len(peers))
	for _, p := range peers {
		if p == self {
			continue
		}
		peerSet[p] = struct{}{}
	}
	return &endpoint{core: newEndpointCore(n, self), peers: peerSet}
}

func (e *endpoint) Send(ctx context.Context, to cbmpc.RoleID, msg []byte) error {
	if to == e.core.self {
		return errors.New("mocknet: send to self")
	}
	if _, ok := e.peers[to]; !ok {
		return fmt.Errorf("mocknet: unknown peer %d", to)
	}
	lock := e.core.sendLock(to)
	lock.Lock()
	defer lock.Unlock()

	seq := e.core.currentSendSeq(to)
	if err := e.core.net.deliver(ctx, e.core.key(e.core.self, to, seq), msg); err != nil {
		return err
	}
	e.core.advanceSendSeq(to)
	return nil
}

func (e *endpoint) Receive(ctx context.Context, from cbmpc.RoleID) ([]byte, error) {
	if from == e.core.self {
		return nil, errors.New("mocknet: receive from self")
	}
	if _, ok := e.peers[from]; !ok {
		return nil, fmt.Errorf("mocknet: unknown peer %d", from)
	}
	lock := e.core.recvLock(from)
	lock.Lock()
	defer lock.Unlock()

	seq := e.core.currentRecvSeq(from)
	msg, err := e.core.net.await(ctx, e.core.key(from, e.core.self, seq))
	if err != nil {
		return nil, err
	}
	e.core.advanceRecvSeq(from)
	return msg, nil
}

func (e *endpoint) ReceiveAll(ctx context.Context, from []cbmpc.RoleID) (map[cbmpc.RoleID][]byte, error) {
	roles, err := e.normalizeRoles(from)
	if err != nil {
		return nil, err
	}
	if len(roles) == 0 {
		return map[cbmpc.RoleID][]byte{}, nil
	}

	locks := make([]*sync.Mutex, len(roles))
	for i, role := range roles {
		lock := e.core.recvLock(role)
		lock.Lock()
		locks[i] = lock
	}
	defer func() {
		for _, lock := range locks {
			lock.Unlock()
		}
	}()

	out := make(map[cbmpc.RoleID][]byte, len(roles))
	for _, role := range roles {
		seq := e.core.currentRecvSeq(role)
		msg, err := e.core.net.await(ctx, e.core.key(role, e.core.self, seq))
		if err != nil {
			return nil, err
		}
		out[role] = msg
		e.core.advanceRecvSeq(role)
	}
	return out, nil
}

func (e *endpoint) normalizeRoles(from []cbmpc.RoleID) ([]cbmpc.RoleID, error) {
	uniq := make(map[cbmpc.RoleID]struct{}, len(from))
	for _, role := range from {
		if role == e.core.self {
			return nil, errors.New("mocknet: receive from self")
		}
		if _, ok := e.peers[role]; !ok {
			return nil, fmt.Errorf("mocknet: unknown peer %d", role)
		}
		if _, ok := uniq[role]; ok {
			return nil, errors.New("mocknet: duplicate role")
		}
		uniq[role] = struct{}{}
	}
	roles := make([]cbmpc.RoleID, 0, len(uniq))
	for role := range uniq {
		roles = append(roles, role)
	}
	sort.Slice(roles, func(i, j int) bool { return roles[i] < roles[j] })
	return roles, nil
}

type (
	Endpoint2P struct{ *endpoint }
	EndpointMP struct{ *endpoint }
)

func (n *Net) Ep2P(self, peer cbmpc.RoleID) *Endpoint2P {
	return &Endpoint2P{endpoint: newEndpoint(n, self, []cbmpc.RoleID{peer})}
}

func (n *Net) EpMP(self cbmpc.RoleID, peers []cbmpc.RoleID) *EndpointMP {
	return &EndpointMP{endpoint: newEndpoint(n, self, peers)}
}

var (
	_ cbmpc.Transport = (*Endpoint2P)(nil)
	_ cbmpc.Transport = (*EndpointMP)(nil)
)
