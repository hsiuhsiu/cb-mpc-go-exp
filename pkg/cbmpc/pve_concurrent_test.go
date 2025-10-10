package cbmpc_test

import (
	"context"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/coinbase/cb-mpc-go/pkg/cbmpc"
	"github.com/coinbase/cb-mpc-go/pkg/cbmpc/internal/testkem"
)

// TestPVEConcurrentOperations tests that multiple PVE instances with different KEMs
// can operate concurrently without interfering with each other.
func TestPVEConcurrentOperations(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	const numGoroutines = 10

	var wg sync.WaitGroup
	errors := make(chan error, numGoroutines)

	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()

			// Each goroutine creates its own KEM and PVE instance
			kem := testkem.NewToyRSAKEM(2048)
			pve, err := cbmpc.NewPVE(kem)
			if err != nil {
				errors <- fmt.Errorf("goroutine %d: failed to create PVE: %v", id, err)
				return
			}

			// Generate unique key pair for this goroutine
			skRef, ek, err := kem.Generate()
			if err != nil {
				errors <- fmt.Errorf("goroutine %d: failed to generate keys: %v", id, err)
				return
			}

			dkHandle, err := kem.NewPrivateKeyHandle(skRef)
			if err != nil {
				errors <- fmt.Errorf("goroutine %d: failed to create handle: %v", id, err)
				return
			}
			defer kem.FreePrivateKeyHandle(dkHandle)

			// Each goroutine encrypts a unique value
			uniqueValue := fmt.Sprintf("%d", id*1000+42)
			x, err := cbmpc.NewScalarFromString(uniqueValue)
			if err != nil {
				errors <- fmt.Errorf("goroutine %d: failed to create scalar: %v", id, err)
				return
			}
			defer x.Free()

			// Encrypt
			encryptResult, err := pve.Encrypt(ctx, &cbmpc.EncryptParams{
				EK:    ek,
				Label: []byte(fmt.Sprintf("test-%d", id)),
				Curve: cbmpc.CurveP256,
				X:     x,
			})
			if err != nil {
				errors <- fmt.Errorf("goroutine %d: encrypt failed: %v", id, err)
				return
			}

			// Decrypt
			decryptResult, err := pve.Decrypt(ctx, &cbmpc.DecryptParams{
				DK:         dkHandle,
				EK:         ek,
				Ciphertext: encryptResult.Ciphertext,
				Label:      []byte(fmt.Sprintf("test-%d", id)),
				Curve:      cbmpc.CurveP256,
			})
			if err != nil {
				errors <- fmt.Errorf("goroutine %d: decrypt failed: %v", id, err)
				return
			}
			defer decryptResult.X.Free()

			// Verify the decrypted value matches
			if x.String() != decryptResult.X.String() {
				errors <- fmt.Errorf("goroutine %d: value mismatch: got %s, want %s",
					id, decryptResult.X.String(), x.String())
				return
			}

			fmt.Printf("Goroutine %d: ✓ Encrypted and decrypted %s\n", id, uniqueValue)
		}(i)
	}

	// Wait for all goroutines to complete
	wg.Wait()
	close(errors)

	// Check for any errors
	for err := range errors {
		t.Error(err)
	}

	if t.Failed() {
		t.Fatal("Concurrent operations failed")
	}

	fmt.Println("✓ All concurrent PVE operations succeeded!")
	fmt.Println("✓ Multiple KEMs can operate concurrently without interference!")
}
