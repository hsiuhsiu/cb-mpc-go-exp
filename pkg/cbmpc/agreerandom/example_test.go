package agreerandom_test

import (
	"context"
	"fmt"
	"log"
	"time"

	"github.com/coinbase/cb-mpc-go/pkg/cbmpc"
	"github.com/coinbase/cb-mpc-go/pkg/cbmpc/agreerandom"
	"github.com/coinbase/cb-mpc-go/pkg/cbmpc/mocknet"
)

// ExampleAgreeRandom demonstrates 2-party random value agreement.
func ExampleAgreeRandom() {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// Setup mock network for two parties
	net := mocknet.New()
	names := [2]string{"alice", "bob"}

	// Alice's job (Role 0)
	aliceTransport := net.Ep2P(cbmpc.RoleID(0), cbmpc.RoleID(1))
	aliceJob, err := cbmpc.NewJob2P(aliceTransport, cbmpc.Role(0), names)
	if err != nil {
		log.Fatal(err)
	}
	defer aliceJob.Close()

	// Bob's job (Role 1)
	bobTransport := net.Ep2P(cbmpc.RoleID(1), cbmpc.RoleID(0))
	bobJob, err := cbmpc.NewJob2P(bobTransport, cbmpc.Role(1), names)
	if err != nil {
		log.Fatal(err)
	}
	defer bobJob.Close()

	// Run protocol in parallel
	type result struct {
		random []byte
		err    error
	}
	aliceCh := make(chan result, 1)
	bobCh := make(chan result, 1)

	go func() {
		random, err := agreerandom.AgreeRandom(ctx, aliceJob, 256)
		aliceCh <- result{random, err}
	}()

	go func() {
		random, err := agreerandom.AgreeRandom(ctx, bobJob, 256)
		bobCh <- result{random, err}
	}()

	aliceResult := <-aliceCh
	bobResult := <-bobCh

	if aliceResult.err != nil || bobResult.err != nil {
		log.Fatalf("AgreeRandom failed: alice=%v, bob=%v", aliceResult.err, bobResult.err)
	}

	// Both parties should have the same 256-bit random value
	fmt.Printf("Random value length: %d bytes\n", len(aliceResult.random))
	fmt.Printf("Values match: %v\n", string(aliceResult.random) == string(bobResult.random))

	// Output:
	// Random value length: 32 bytes
	// Values match: true
}

// ExampleMultiAgreeRandom demonstrates multi-party random value agreement.
func ExampleMultiAgreeRandom() {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// Setup mock network for three parties
	net := mocknet.New()
	names := []string{"alice", "bob", "carol"}

	// Create jobs for all parties
	allParties := []cbmpc.RoleID{0, 1, 2}
	jobs := make([]*cbmpc.JobMP, 3)
	for i := range jobs {
		transport := net.EpMP(cbmpc.RoleID(i), allParties)
		job, err := cbmpc.NewJobMP(transport, cbmpc.RoleID(i), names)
		if err != nil {
			log.Fatal(err)
		}
		defer job.Close()
		jobs[i] = job
	}

	// Run protocol in parallel
	type result struct {
		random []byte
		err    error
	}
	results := make([]chan result, 3)
	for i := range results {
		results[i] = make(chan result, 1)
		go func(idx int) {
			random, err := agreerandom.MultiAgreeRandom(ctx, jobs[idx], 256)
			results[idx] <- result{random, err}
		}(i)
	}

	// Collect results
	outputs := make([][]byte, 3)
	for i := range results {
		r := <-results[i]
		if r.err != nil {
			log.Fatalf("Party %d failed: %v", i, r.err)
		}
		outputs[i] = r.random
	}

	// All parties should have the same random value
	fmt.Printf("Random value length: %d bytes\n", len(outputs[0]))
	fmt.Printf("All values match: %v\n",
		string(outputs[0]) == string(outputs[1]) && string(outputs[1]) == string(outputs[2]))

	// Output:
	// Random value length: 32 bytes
	// All values match: true
}
