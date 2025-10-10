package pve_test

import (
	"context"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/coinbase/cb-mpc-go/pkg/cbmpc"
	"github.com/coinbase/cb-mpc-go/pkg/cbmpc/internal/testkem"
	"github.com/coinbase/cb-mpc-go/pkg/cbmpc/pve"
)

// TestPVEKEMIsolation verifies that KEMs are properly isolated between goroutines
// and that one goroutine's KEM doesn't affect another's operations.
func TestPVEKEMIsolation(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Create two different KEMs with different key sizes
	// This helps us detect if one goroutine accidentally uses the other's KEM
	kem1 := testkem.NewToyRSAKEM(2048)
	kem2 := testkem.NewToyRSAKEM(3072)

	pve1, _ := pve.New(kem1)
	pve2, _ := pve.New(kem2)

	// Generate separate key pairs
	skRef1, ek1, _ := kem1.Generate()
	skRef2, ek2, _ := kem2.Generate()

	dk1, _ := kem1.NewPrivateKeyHandle(skRef1)
	defer kem1.FreePrivateKeyHandle(dk1)

	dk2, _ := kem2.NewPrivateKeyHandle(skRef2)
	defer kem2.FreePrivateKeyHandle(dk2)

	x1, _ := cbmpc.NewScalarFromString("111")
	defer x1.Free()

	x2, _ := cbmpc.NewScalarFromString("222")
	defer x2.Free()

	var wg sync.WaitGroup
	errors := make(chan error, 2)

	// Goroutine 1: Uses PVE with KEM1
	wg.Add(1)
	go func() {
		defer wg.Done()

		// Introduce some delay to ensure operations overlap
		time.Sleep(10 * time.Millisecond)

		encResult, err := pve1.Encrypt(ctx, &pve.EncryptParams{
			EK:    ek1,
			Label: []byte("kem1"),
			Curve: cbmpc.CurveP256,
			X:     x1,
		})
		if err != nil {
			errors <- fmt.Errorf("goroutine 1 encrypt failed: %v", err)
			return
		}

		time.Sleep(5 * time.Millisecond) // Allow time for interleaving

		decResult, err := pve1.Decrypt(ctx, &pve.DecryptParams{
			DK:         dk1,
			EK:         ek1,
			Ciphertext: encResult.Ciphertext,
			Label:      []byte("kem1"),
			Curve:      cbmpc.CurveP256,
		})
		if err != nil {
			errors <- fmt.Errorf("goroutine 1 decrypt failed: %v", err)
			return
		}
		defer decResult.X.Free()

		if x1.String() != decResult.X.String() {
			errors <- fmt.Errorf("goroutine 1: value mismatch: got %s, want %s",
				decResult.X.String(), x1.String())
			return
		}

		fmt.Println("Goroutine 1: ✓ Successfully used KEM1")
	}()

	// Goroutine 2: Uses PVE with KEM2
	wg.Add(1)
	go func() {
		defer wg.Done()

		// Different delay pattern
		time.Sleep(5 * time.Millisecond)

		encResult, err := pve2.Encrypt(ctx, &pve.EncryptParams{
			EK:    ek2,
			Label: []byte("kem2"),
			Curve: cbmpc.CurveSecp256k1,
			X:     x2,
		})
		if err != nil {
			errors <- fmt.Errorf("goroutine 2 encrypt failed: %v", err)
			return
		}

		time.Sleep(10 * time.Millisecond) // Allow time for interleaving

		decResult, err := pve2.Decrypt(ctx, &pve.DecryptParams{
			DK:         dk2,
			EK:         ek2,
			Ciphertext: encResult.Ciphertext,
			Label:      []byte("kem2"),
			Curve:      cbmpc.CurveSecp256k1,
		})
		if err != nil {
			errors <- fmt.Errorf("goroutine 2 decrypt failed: %v", err)
			return
		}
		defer decResult.X.Free()

		if x2.String() != decResult.X.String() {
			errors <- fmt.Errorf("goroutine 2: value mismatch: got %s, want %s",
				decResult.X.String(), x2.String())
			return
		}

		fmt.Println("Goroutine 2: ✓ Successfully used KEM2")
	}()

	wg.Wait()
	close(errors)

	for err := range errors {
		t.Error(err)
	}

	if !t.Failed() {
		fmt.Println("✓ KEMs are properly isolated between goroutines!")
		fmt.Println("✓ No cross-contamination between concurrent operations!")
	}
}
