package main

import (
	"context"
	"fmt"
	"log"
	"sync"

	"github.com/coinbase/cb-mpc-go/pkg/mpc"
)

func main() {
	// Example 1: Two-party agree random
	fmt.Println("=== Two-Party Agree Random ===")
	twoPartyExample()

	fmt.Println()

	// Example 2: Multi-party agree random with 3 parties
	fmt.Println("=== Three-Party Agree Random ===")
	threePartyExample()

	fmt.Println()

	// Example 3: Multi-party agree random with 5 parties
	fmt.Println("=== Five-Party Agree Random ===")
	fivePartyExample()
}

func twoPartyExample() {
	// Create a mock network with 2 parties
	sessions := mpc.NewMockNetwork(2)

	// Parameters
	bitLen := 256
	ctx := context.Background()

	// Run the protocol in parallel for both parties
	var wg sync.WaitGroup
	results := make([][]byte, 2)
	errs := make([]error, 2)

	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func(partyIndex int) {
			defer wg.Done()
			result, err := mpc.AgreeRandom2PC(ctx, sessions[partyIndex], bitLen)
			results[partyIndex] = result
			errs[partyIndex] = err
		}(i)
	}

	wg.Wait()

	// Check results
	for i, err := range errs {
		if err != nil {
			log.Fatalf("Party %d failed: %v", i, err)
		}
	}

	// Verify both parties got the same result
	fmt.Printf("Party 0 result: %x\n", results[0][:8])
	fmt.Printf("Party 1 result: %x\n", results[1][:8])
	fmt.Printf("Results match: %v\n", bytesEqual(results[0], results[1]))
	fmt.Printf("Random value length: %d bytes (%d bits)\n", len(results[0]), len(results[0])*8)
}

func threePartyExample() {
	// Create a mock network with 3 parties
	sessions := mpc.NewMockNetwork(3)

	// Parameters
	bitLen := 128
	ctx := context.Background()

	// Run the protocol in parallel for all parties
	var wg sync.WaitGroup
	results := make([][]byte, 3)
	errs := make([]error, 3)

	for i := 0; i < 3; i++ {
		wg.Add(1)
		go func(partyIndex int) {
			defer wg.Done()
			result, err := mpc.AgreeRandomMPC(ctx, sessions[partyIndex], bitLen)
			results[partyIndex] = result
			errs[partyIndex] = err
		}(i)
	}

	wg.Wait()

	// Check results
	for i, err := range errs {
		if err != nil {
			log.Fatalf("Party %d failed: %v", i, err)
		}
	}

	// Verify all parties got the same result
	for i := 0; i < 3; i++ {
		fmt.Printf("Party %d result: %x\n", i, results[i][:8])
	}

	allMatch := true
	for i := 1; i < 3; i++ {
		if !bytesEqual(results[0], results[i]) {
			allMatch = false
			break
		}
	}
	fmt.Printf("All results match: %v\n", allMatch)
	fmt.Printf("Random value length: %d bytes (%d bits)\n", len(results[0]), len(results[0])*8)
}

func fivePartyExample() {
	// Create a mock network with 5 parties
	sessions := mpc.NewMockNetwork(5)

	// Parameters
	bitLen := 512
	ctx := context.Background()

	// Run the protocol in parallel for all parties
	var wg sync.WaitGroup
	results := make([][]byte, 5)
	errs := make([]error, 5)

	for i := 0; i < 5; i++ {
		wg.Add(1)
		go func(partyIndex int) {
			defer wg.Done()
			result, err := mpc.AgreeRandomMPC(ctx, sessions[partyIndex], bitLen)
			results[partyIndex] = result
			errs[partyIndex] = err
		}(i)
	}

	wg.Wait()

	// Check results
	for i, err := range errs {
		if err != nil {
			log.Fatalf("Party %d failed: %v", i, err)
		}
	}

	// Verify all parties got the same result
	fmt.Printf("Party 0 result: %x...\n", results[0][:8])
	fmt.Printf("Party 1 result: %x...\n", results[1][:8])
	fmt.Printf("Party 2 result: %x...\n", results[2][:8])
	fmt.Printf("Party 3 result: %x...\n", results[3][:8])
	fmt.Printf("Party 4 result: %x...\n", results[4][:8])

	allMatch := true
	for i := 1; i < 5; i++ {
		if !bytesEqual(results[0], results[i]) {
			allMatch = false
			break
		}
	}
	fmt.Printf("All results match: %v\n", allMatch)
	fmt.Printf("Random value length: %d bytes (%d bits)\n", len(results[0]), len(results[0])*8)
}

func bytesEqual(a, b []byte) bool {
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
