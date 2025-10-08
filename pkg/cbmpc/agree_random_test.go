//go:build cgo && !windows

package cbmpc_test

import (
	"context"
	"sync"
	"testing"
	"time"

	cbmpc "github.com/coinbase/cb-mpc-go/pkg/cbmpc"
	"github.com/coinbase/cb-mpc-go/pkg/cbmpc/mocknet"
)

func TestAgreeRandom2PNative(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	net := mocknet.New()

	p1 := net.Ep2P(cbmpc.RoleID(cbmpc.RoleP1), cbmpc.RoleID(cbmpc.RoleP2))
	p2 := net.Ep2P(cbmpc.RoleID(cbmpc.RoleP2), cbmpc.RoleID(cbmpc.RoleP1))

	names := [2]string{"p1", "p2"}

	job1, err := cbmpc.NewJob2P(p1, cbmpc.RoleP1, names)
	if err != nil {
		t.Fatalf("NewJob2P p1: %v", err)
	}
	defer func() {
		_ = job1.Close()
	}()

	job2, err := cbmpc.NewJob2P(p2, cbmpc.RoleP2, names)
	if err != nil {
		_ = job1.Close()
		t.Fatalf("NewJob2P p2: %v", err)
	}
	defer func() {
		_ = job2.Close()
	}()

	var (
		wg   sync.WaitGroup
		out1 []byte
		out2 []byte
		err1 error
		err2 error
	)

	wg.Add(2)
	go func() {
		defer wg.Done()
		out1, err1 = cbmpc.AgreeRandom(ctx, job1, 256)
	}()
	go func() {
		defer wg.Done()
		out2, err2 = cbmpc.AgreeRandom(ctx, job2, 256)
	}()
	wg.Wait()

	if err1 != nil {
		t.Fatalf("AgreeRandom p1: %v", err1)
	}
	if err2 != nil {
		t.Fatalf("AgreeRandom p2: %v", err2)
	}

	if len(out1) != 32 || len(out2) != 32 {
		t.Fatalf("expected 32-byte outputs, got %d and %d", len(out1), len(out2))
	}
	if !equalBytes(out1, out2) {
		t.Fatalf("party outputs differ\np1=%x\np2=%x", out1, out2)
	}
}

func TestMultiAgreeRandomNative(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	net := mocknet.New()

	roles := []cbmpc.RoleID{0, 1, 2}
	names := []string{"mp1", "mp2", "mp3"}

	type result struct {
		bytes []byte
		err   error
	}

	outputs := make([]result, len(roles))
	jobs := make([]*cbmpc.JobMP, len(roles))

	for i, self := range roles {
		peers := make([]cbmpc.RoleID, 0, len(roles)-1)
		for j, r := range roles {
			if j == int(self) {
				continue
			}
			peers = append(peers, r)
		}
		ep := net.EpMP(self, peers)
		job, err := cbmpc.NewJobMP(ep, self, names)
		if err != nil {
			for j := 0; j < i; j++ {
				if jobs[j] != nil {
					_ = jobs[j].Close()
				}
			}
			t.Fatalf("NewJobMP role %d: %v", self, err)
		}
		jobs[i] = job
	}
	defer func() {
		for _, job := range jobs {
			_ = job.Close()
		}
	}()

	bitlen := 256
	var wg sync.WaitGroup
	wg.Add(len(roles))
	for idx, job := range jobs {
		i := idx
		go func() {
			defer wg.Done()
			outputs[i].bytes, outputs[i].err = cbmpc.MultiAgreeRandom(ctx, job, bitlen)
		}()
	}
	wg.Wait()

	for i, res := range outputs {
		if res.err != nil {
			t.Fatalf("MultiAgreeRandom role %d: %v", roles[i], res.err)
		}
		if len(res.bytes) != bitlen/8 {
			t.Fatalf("unexpected output length for role %d: %d", roles[i], len(res.bytes))
		}
	}

	reference := outputs[0].bytes
	for i := 1; i < len(outputs); i++ {
		if !equalBytes(reference, outputs[i].bytes) {
			t.Fatalf("outputs differ: role %d != role %d", roles[0], roles[i])
		}
	}
}

func TestWeakMultiAgreeRandomNative(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	net := mocknet.New()

	roles := []cbmpc.RoleID{0, 1, 2}
	names := []string{"mp1", "mp2", "mp3"}

	type result struct {
		bytes []byte
		err   error
	}

	outputs := make([]result, len(roles))
	jobs := make([]*cbmpc.JobMP, len(roles))

	for i, self := range roles {
		peers := make([]cbmpc.RoleID, 0, len(roles)-1)
		for j, r := range roles {
			if j == int(self) {
				continue
			}
			peers = append(peers, r)
		}
		ep := net.EpMP(self, peers)
		job, err := cbmpc.NewJobMP(ep, self, names)
		if err != nil {
			for j := 0; j < i; j++ {
				if jobs[j] != nil {
					_ = jobs[j].Close()
				}
			}
			t.Fatalf("NewJobMP role %d: %v", self, err)
		}
		jobs[i] = job
	}
	defer func() {
		for _, job := range jobs {
			_ = job.Close()
		}
	}()

	bitlen := 256
	var wg sync.WaitGroup
	wg.Add(len(roles))
	for idx, job := range jobs {
		i := idx
		go func() {
			defer wg.Done()
			outputs[i].bytes, outputs[i].err = cbmpc.WeakMultiAgreeRandom(ctx, job, bitlen)
		}()
	}
	wg.Wait()

	for i, res := range outputs {
		if res.err != nil {
			t.Fatalf("WeakMultiAgreeRandom role %d: %v", roles[i], res.err)
		}
		if len(res.bytes) != bitlen/8 {
			t.Fatalf("unexpected output length for role %d: %d", roles[i], len(res.bytes))
		}
	}

	reference := outputs[0].bytes
	for i := 1; i < len(outputs); i++ {
		if !equalBytes(reference, outputs[i].bytes) {
			t.Fatalf("outputs differ: role %d != role %d", roles[0], roles[i])
		}
	}
}

func TestMultiPairwiseAgreeRandomNative(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	net := mocknet.New()

	roles := []cbmpc.RoleID{0, 1, 2}
	names := []string{"mp1", "mp2", "mp3"}

	type result struct {
		bytesSlice [][]byte
		err        error
	}

	outputs := make([]result, len(roles))
	jobs := make([]*cbmpc.JobMP, len(roles))

	for i, self := range roles {
		peers := make([]cbmpc.RoleID, 0, len(roles)-1)
		for j, r := range roles {
			if j == int(self) {
				continue
			}
			peers = append(peers, r)
		}
		ep := net.EpMP(self, peers)
		job, err := cbmpc.NewJobMP(ep, self, names)
		if err != nil {
			for j := 0; j < i; j++ {
				if jobs[j] != nil {
					_ = jobs[j].Close()
				}
			}
			t.Fatalf("NewJobMP role %d: %v", self, err)
		}
		jobs[i] = job
	}
	defer func() {
		for _, job := range jobs {
			_ = job.Close()
		}
	}()

	bitlen := 256
	var wg sync.WaitGroup
	wg.Add(len(roles))
	for idx, job := range jobs {
		i := idx
		go func() {
			defer wg.Done()
			outputs[i].bytesSlice, outputs[i].err = cbmpc.MultiPairwiseAgreeRandom(ctx, job, bitlen)
		}()
	}
	wg.Wait()

	for i, res := range outputs {
		if res.err != nil {
			t.Fatalf("MultiPairwiseAgreeRandom role %d: %v", roles[i], res.err)
		}
		// Each party should get n random values (one for each party including self)
		expectedCount := len(roles)
		if len(res.bytesSlice) != expectedCount {
			t.Fatalf("unexpected output count for role %d: got %d, expected %d", roles[i], len(res.bytesSlice), expectedCount)
		}
		for j, bytes := range res.bytesSlice {
			if len(bytes) != bitlen/8 {
				t.Fatalf("unexpected output length for role %d, peer %d: %d", roles[i], j, len(bytes))
			}
		}
	}

	// Verify pairwise consistency: party i's j-th output should match party j's i-th output
	for i := 0; i < len(roles); i++ {
		for j := 0; j < len(roles); j++ {
			if i == j {
				continue
			}

			if !equalBytes(outputs[i].bytesSlice[j], outputs[j].bytesSlice[i]) {
				t.Fatalf("pairwise random mismatch: party %d output[%d] != party %d output[%d]",
					roles[i], j, roles[j], i)
			}
		}
	}
}

func equalBytes(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
