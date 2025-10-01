package mpc

import (
	"context"
	"sync"
	"testing"
)

func TestAgreeRandom2PC(t *testing.T) {
	// Create mock network with 2 parties
	sessions := NewMockNetwork(2)

	bitLen := 256
	ctx := context.Background()

	// Run protocol in parallel for both parties
	var wg sync.WaitGroup
	results := make([][]byte, 2)
	errs := make([]error, 2)

	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func(partyIndex int) {
			defer wg.Done()
			result, err := AgreeRandom2PC(ctx, sessions[partyIndex], bitLen)
			results[partyIndex] = result
			errs[partyIndex] = err
		}(i)
	}

	wg.Wait()

	// Check for errors
	for i, err := range errs {
		if err != nil {
			t.Fatalf("Party %d failed: %v", i, err)
		}
	}

	// Verify both parties got the same result
	if len(results[0]) == 0 {
		t.Fatal("Party 0 got empty result")
	}

	if len(results[1]) == 0 {
		t.Fatal("Party 1 got empty result")
	}

	if len(results[0]) != len(results[1]) {
		t.Fatalf("Result lengths differ: %d vs %d", len(results[0]), len(results[1]))
	}

	for i := range results[0] {
		if results[0][i] != results[1][i] {
			t.Fatalf("Results differ at byte %d: %x vs %x", i, results[0][i], results[1][i])
		}
	}

	// Verify result is approximately the right size (bitLen/8 bytes)
	expectedBytes := (bitLen + 7) / 8
	if len(results[0]) != expectedBytes {
		t.Logf("Warning: Expected ~%d bytes for %d bits, got %d bytes", expectedBytes, bitLen, len(results[0]))
	}

	t.Logf("Success: Both parties agreed on %d-byte random value", len(results[0]))
}

func TestAgreeRandom2PC_DifferentBitLengths(t *testing.T) {
	testCases := []struct {
		name   string
		bitLen int
	}{
		{"128 bits", 128},
		{"256 bits", 256},
		{"512 bits", 512},
		{"1024 bits", 1024},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			sessions := NewMockNetwork(2)
			ctx := context.Background()

			var wg sync.WaitGroup
			results := make([][]byte, 2)
			errs := make([]error, 2)

			for i := 0; i < 2; i++ {
				wg.Add(1)
				go func(partyIndex int) {
					defer wg.Done()
					result, err := AgreeRandom2PC(ctx, sessions[partyIndex], tc.bitLen)
					results[partyIndex] = result
					errs[partyIndex] = err
				}(i)
			}

			wg.Wait()

			for i, err := range errs {
				if err != nil {
					t.Fatalf("Party %d failed: %v", i, err)
				}
			}

			if len(results[0]) != len(results[1]) {
				t.Fatalf("Result lengths differ: %d vs %d", len(results[0]), len(results[1]))
			}

			for i := range results[0] {
				if results[0][i] != results[1][i] {
					t.Fatalf("Results differ")
				}
			}
		})
	}
}

func TestAgreeRandomMPC_ThreeParties(t *testing.T) {
	// Create mock network with 3 parties
	sessions := NewMockNetwork(3)

	bitLen := 256
	ctx := context.Background()

	// Run protocol in parallel for all parties
	var wg sync.WaitGroup
	results := make([][]byte, 3)
	errs := make([]error, 3)

	for i := 0; i < 3; i++ {
		wg.Add(1)
		go func(partyIndex int) {
			defer wg.Done()
			result, err := AgreeRandomMPC(ctx, sessions[partyIndex], bitLen)
			results[partyIndex] = result
			errs[partyIndex] = err
		}(i)
	}

	wg.Wait()

	// Check for errors
	for i, err := range errs {
		if err != nil {
			t.Fatalf("Party %d failed: %v", i, err)
		}
	}

	// Verify all parties got the same result
	for i := 0; i < 3; i++ {
		if len(results[i]) == 0 {
			t.Fatalf("Party %d got empty result", i)
		}
	}

	// Compare all results
	for i := 1; i < 3; i++ {
		if len(results[0]) != len(results[i]) {
			t.Fatalf("Result lengths differ between party 0 and party %d: %d vs %d", i, len(results[0]), len(results[i]))
		}

		for j := range results[0] {
			if results[0][j] != results[i][j] {
				t.Fatalf("Results differ between party 0 and party %d at byte %d", i, j)
			}
		}
	}

	t.Logf("Success: All 3 parties agreed on %d-byte random value", len(results[0]))
}

func TestAgreeRandomMPC_FiveParties(t *testing.T) {
	// Create mock network with 5 parties
	sessions := NewMockNetwork(5)

	bitLen := 128
	ctx := context.Background()

	// Run protocol in parallel for all parties
	var wg sync.WaitGroup
	results := make([][]byte, 5)
	errs := make([]error, 5)

	for i := 0; i < 5; i++ {
		wg.Add(1)
		go func(partyIndex int) {
			defer wg.Done()
			result, err := AgreeRandomMPC(ctx, sessions[partyIndex], bitLen)
			results[partyIndex] = result
			errs[partyIndex] = err
		}(i)
	}

	wg.Wait()

	// Check for errors
	for i, err := range errs {
		if err != nil {
			t.Fatalf("Party %d failed: %v", i, err)
		}
	}

	// Verify all parties got the same result
	for i := 1; i < 5; i++ {
		if len(results[0]) != len(results[i]) {
			t.Fatalf("Result lengths differ")
		}

		for j := range results[0] {
			if results[0][j] != results[i][j] {
				t.Fatalf("Results differ between parties")
			}
		}
	}

	t.Logf("Success: All 5 parties agreed on %d-byte random value", len(results[0]))
}

func TestAgreeRandom2PC_InvalidInputs(t *testing.T) {
	sessions := NewMockNetwork(2)
	ctx := context.Background()

	// Test with nil session
	_, err := AgreeRandom2PC(ctx, nil, 256)
	if err == nil {
		t.Error("Expected error with nil session")
	}

	// Test with invalid bitLen
	_, err = AgreeRandom2PC(ctx, sessions[0], 0)
	if err == nil {
		t.Error("Expected error with bitLen=0")
	}

	_, err = AgreeRandom2PC(ctx, sessions[0], -1)
	if err == nil {
		t.Error("Expected error with negative bitLen")
	}
}

func TestAgreeRandomMPC_InvalidInputs(t *testing.T) {
	sessions := NewMockNetwork(3)
	ctx := context.Background()

	// Test with nil session
	_, err := AgreeRandomMPC(ctx, nil, 256)
	if err == nil {
		t.Error("Expected error with nil session")
	}

	// Test with invalid bitLen
	_, err = AgreeRandomMPC(ctx, sessions[0], 0)
	if err == nil {
		t.Error("Expected error with bitLen=0")
	}
}

// bytesEqual compares two byte slices for equality
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

func TestMockSession(t *testing.T) {
	// Test basic mock session functionality
	sessions := NewMockNetwork(3)

	// Verify party indices
	for i, session := range sessions {
		if session.MyIndex() != i {
			t.Errorf("Party %d has wrong index: %d", i, session.MyIndex())
		}
		if session.PartyCount() != 3 {
			t.Errorf("Party %d reports wrong party count: %d", i, session.PartyCount())
		}
	}

	// Test send/receive
	msg := []byte("test message")
	err := sessions[0].Send(1, msg)
	if err != nil {
		t.Fatalf("Send failed: %v", err)
	}

	received, err := sessions[1].Receive(0)
	if err != nil {
		t.Fatalf("Receive failed: %v", err)
	}

	if string(received) != string(msg) {
		t.Errorf("Received wrong message: got %s, want %s", received, msg)
	}

	// Test ReceiveAll
	err = sessions[0].Send(2, []byte("msg1"))
	if err != nil {
		t.Fatal(err)
	}
	err = sessions[1].Send(2, []byte("msg2"))
	if err != nil {
		t.Fatal(err)
	}

	messages, err := sessions[2].ReceiveAll([]int{0, 1})
	if err != nil {
		t.Fatalf("ReceiveAll failed: %v", err)
	}

	if len(messages) != 2 {
		t.Fatalf("Expected 2 messages, got %d", len(messages))
	}

	if string(messages[0]) != "msg1" || string(messages[1]) != "msg2" {
		t.Errorf("Wrong messages received: %v", messages)
	}
}
