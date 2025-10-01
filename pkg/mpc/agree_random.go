package mpc

import (
	"context"
	"fmt"

	"github.com/coinbase/cb-mpc-go/internal/cgo"
)

// AgreeRandom2PC executes a two-party agree random protocol
// Both parties will agree on the same random value of bitLen bits
//
// This is one of the simplest MPC protocols and is useful for:
//   - Generating shared randomness for other protocols
//   - Testing and validating MPC infrastructure
//   - Learning about MPC protocol execution
func AgreeRandom2PC(ctx context.Context, session Session, bitLen int) ([]byte, error) {
	if session == nil {
		return nil, fmt.Errorf("session cannot be nil")
	}

	if bitLen <= 0 {
		return nil, fmt.Errorf("bitLen must be positive, got %d", bitLen)
	}

	if session.PartyCount() != 2 {
		return nil, fmt.Errorf("AgreeRandom2PC requires exactly 2 parties, got %d", session.PartyCount())
	}

	// Create party names
	partyNames := []string{"party0", "party1"}

	// Create job
	job, err := cgo.NewJob2P(session, session.MyIndex(), partyNames)
	if err != nil {
		return nil, fmt.Errorf("failed to create 2P job: %w", err)
	}
	defer job.Close()

	// Execute protocol
	randomValue, err := cgo.AgreeRandom(job, bitLen)
	if err != nil {
		return nil, fmt.Errorf("agree random protocol failed: %w", err)
	}

	return randomValue, nil
}

// AgreeRandomMPC executes a multi-party agree random protocol
// All parties will agree on the same random value of bitLen bits
//
// This protocol works with any number of parties >= 2
func AgreeRandomMPC(ctx context.Context, session Session, bitLen int) ([]byte, error) {
	if session == nil {
		return nil, fmt.Errorf("session cannot be nil")
	}

	if bitLen <= 0 {
		return nil, fmt.Errorf("bitLen must be positive, got %d", bitLen)
	}

	partyCount := session.PartyCount()
	if partyCount < 2 {
		return nil, fmt.Errorf("AgreeRandomMPC requires at least 2 parties, got %d", partyCount)
	}

	// Create party names
	partyNames := make([]string, partyCount)
	for i := 0; i < partyCount; i++ {
		partyNames[i] = fmt.Sprintf("party%d", i)
	}

	// Create job
	job, err := cgo.NewJobMP(session, partyCount, session.MyIndex(), partyNames)
	if err != nil {
		return nil, fmt.Errorf("failed to create MP job: %w", err)
	}
	defer job.Close()

	// Execute protocol
	randomValue, err := cgo.MultiAgreeRandom(job, bitLen)
	if err != nil {
		return nil, fmt.Errorf("multi agree random protocol failed: %w", err)
	}

	return randomValue, nil
}
