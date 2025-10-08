package mocknet

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/coinbase/cb-mpc-go/pkg/cbmpc"
)

func TestNetEp2PSequenceAndPairing(t *testing.T) {
	net := New()

	p1 := net.Ep2P(cbmpc.RoleID(cbmpc.RoleP1), cbmpc.RoleID(cbmpc.RoleP2))
	p2 := net.Ep2P(cbmpc.RoleID(cbmpc.RoleP2), cbmpc.RoleID(cbmpc.RoleP1))

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	const rounds = 5
	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		defer wg.Done()
		for i := 0; i < rounds; i++ {
			msg := []byte{byte(i)}
			if err := p1.Send(ctx, cbmpc.RoleID(cbmpc.RoleP2), msg); err != nil {
				t.Errorf("p1 send %d: %v", i, err)
				return
			}
			got, err := p1.Receive(ctx, cbmpc.RoleID(cbmpc.RoleP2))
			if err != nil {
				t.Errorf("p1 receive %d: %v", i, err)
				return
			}
			if len(got) != 1 || got[0] != byte(i+1) {
				t.Errorf("p1 receive %d got %v", i, got)
				return
			}
		}
	}()

	go func() {
		defer wg.Done()
		for i := 0; i < rounds; i++ {
			got, err := p2.Receive(ctx, cbmpc.RoleID(cbmpc.RoleP1))
			if err != nil {
				t.Errorf("p2 receive %d: %v", i, err)
				return
			}
			if len(got) != 1 || got[0] != byte(i) {
				t.Errorf("p2 receive %d got %v", i, got)
				return
			}
			msg := []byte{byte(i + 1)}
			if err := p2.Send(ctx, cbmpc.RoleID(cbmpc.RoleP1), msg); err != nil {
				t.Errorf("p2 send %d: %v", i, err)
				return
			}
		}
	}()

	wg.Wait()
}

func TestNetEp2PReceiveAll(t *testing.T) {
	net := New()
	p1 := net.Ep2P(cbmpc.RoleID(cbmpc.RoleP1), cbmpc.RoleID(cbmpc.RoleP2))
	p2 := net.Ep2P(cbmpc.RoleID(cbmpc.RoleP2), cbmpc.RoleID(cbmpc.RoleP1))

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	go func() {
		_ = p2.Send(ctx, cbmpc.RoleID(cbmpc.RoleP1), []byte("hello"))
	}()

	batch, err := p1.ReceiveAll(ctx, []cbmpc.RoleID{cbmpc.RoleID(cbmpc.RoleP2)})
	if err != nil {
		t.Fatalf("ReceiveAll: %v", err)
	}

	msg, ok := batch[cbmpc.RoleID(cbmpc.RoleP2)]
	if !ok || string(msg) != "hello" {
		t.Fatalf("unexpected batch: %+v", batch)
	}

	if _, err := p1.ReceiveAll(ctx, []cbmpc.RoleID{}); err != nil {
		t.Fatalf("empty receiveAll should succeed: %v", err)
	}

	if _, err := p1.ReceiveAll(ctx, []cbmpc.RoleID{cbmpc.RoleID(cbmpc.RoleP1)}); err == nil {
		t.Fatalf("expected error receiving from self")
	}
}

func TestNetEpMPSynchronisation(t *testing.T) {
	net := New()
	roles := []cbmpc.RoleID{0, 1, 2}

	eps := make([]*EndpointMP, len(roles))
	for i, self := range roles {
		peers := make([]cbmpc.RoleID, 0, len(roles)-1)
		for _, r := range roles {
			if r != self {
				peers = append(peers, r)
			}
		}
		eps[i] = net.EpMP(self, peers)
	}

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	var wg sync.WaitGroup
	wg.Add(len(roles))

	for idx, ep := range eps {
		i := idx
		go func() {
			defer wg.Done()
			for _, peer := range roles {
				if peer == roles[i] {
					continue
				}
				if err := ep.Send(ctx, peer, []byte{byte(i)}); err != nil {
					t.Errorf("send %d->%d: %v", i, peer, err)
					return
				}
			}
			expect := make([]cbmpc.RoleID, 0, len(roles)-1)
			for _, peer := range roles {
				if peer != roles[i] {
					expect = append(expect, peer)
				}
			}
			batch, err := ep.ReceiveAll(ctx, expect)
			if err != nil {
				t.Errorf("receiveAll %d: %v", i, err)
				return
			}
			if len(batch) != len(expect) {
				t.Errorf("receiveAll %d size mismatch", i)
			}
			for _, peer := range expect {
				msg, ok := batch[peer]
				if !ok || len(msg) != 1 {
					t.Errorf("receiveAll %d missing peer %d", i, peer)
					return
				}
				if msg[0] != byte(peer) {
					t.Errorf("receiveAll %d got %d from %d", i, msg[0], peer)
				}
			}
		}()
	}

	wg.Wait()
}

func TestReceiveErrors(t *testing.T) {
	net := New()
	ep := net.Ep2P(cbmpc.RoleID(cbmpc.RoleP1), cbmpc.RoleID(cbmpc.RoleP2))

	if err := ep.Send(context.Background(), cbmpc.RoleID(cbmpc.RoleP1), nil); err == nil {
		t.Fatalf("expected send-to-self error")
	}

	if _, err := ep.Receive(context.Background(), cbmpc.RoleID(cbmpc.RoleP1)); err == nil {
		t.Fatalf("expected receive-from-self error")
	}

	mp := net.EpMP(0, []cbmpc.RoleID{1, 2})

	if _, err := mp.ReceiveAll(context.Background(), []cbmpc.RoleID{0, 1}); err == nil {
		t.Fatalf("expected error including self in ReceiveAll")
	}

	if _, err := mp.ReceiveAll(context.Background(), []cbmpc.RoleID{1, 1}); err == nil {
		t.Fatalf("expected duplicate error in ReceiveAll")
	}
}
