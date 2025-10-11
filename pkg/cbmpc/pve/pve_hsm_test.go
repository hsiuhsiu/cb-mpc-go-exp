package pve_test

import (
	"context"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/coinbase/cb-mpc-go/pkg/cbmpc"
	"github.com/coinbase/cb-mpc-go/pkg/cbmpc/curve"
	"github.com/coinbase/cb-mpc-go/pkg/cbmpc/internal/testkem"
	"github.com/coinbase/cb-mpc-go/pkg/cbmpc/pve"
)

// TestPVEWithHSMKEM tests PVE with a simulated HSM KEM.
// This demonstrates how to integrate PVE with hardware security modules
// where private keys never leave secure hardware.
func TestPVEWithHSMKEM(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Create HSM-based KEM
	hsmKEM := testkem.NewHSMKEM(2048)

	// Create PVE instance with HSM KEM
	pveInstance, err := pve.New(hsmKEM)
	if err != nil {
		t.Fatalf("Failed to create PVE instance: %v", err)
	}

	// Generate key pair using HSM
	skRef, ek, err := hsmKEM.Generate()
	if err != nil {
		t.Fatalf("Failed to generate HSM key pair: %v", err)
	}

	// Create private key handle (key stays in HSM)
	dkHandle, err := hsmKEM.NewPrivateKeyHandle(skRef)
	if err != nil {
		t.Fatalf("Failed to create HSM private key handle: %v", err)
	}
	defer func() {
		_ = hsmKEM.FreePrivateKeyHandle(dkHandle)
	}()

	// Test encryption/decryption
	label := []byte("hsm-test")
	x, err := curve.NewScalarFromString("98765432109876543210")
	if err != nil {
		t.Fatalf("Failed to create scalar: %v", err)
	}
	defer x.Free()

	// Encrypt
	encryptResult, err := pveInstance.Encrypt(ctx, &pve.EncryptParams{
		EK:    ek,
		Label: label,
		Curve: cbmpc.CurveP256,
		X:     x,
	})
	if err != nil {
		t.Fatalf("Encrypt failed: %v", err)
	}

	// Decrypt (private key operation happens inside HSM)
	decryptResult, err := pveInstance.Decrypt(ctx, &pve.DecryptParams{
		DK:         dkHandle,
		EK:         ek,
		Ciphertext: encryptResult.Ciphertext,
		Label:      label,
		Curve:      cbmpc.CurveP256,
	})
	if err != nil {
		t.Fatalf("Decrypt failed: %v", err)
	}
	defer decryptResult.X.Free()

	// Verify decryption
	if x.String() != decryptResult.X.String() {
		t.Fatalf("Decrypted value mismatch: got %s, want %s", decryptResult.X.String(), x.String())
	}

	fmt.Println("✓ HSM KEM integration works!")
	fmt.Println("✓ Private key never left the simulated HSM!")
}

// TestPVEMultipleKEMsConcurrent tests that multiple different KEMs
// (HSM KEM and Toy RSA KEM) can be used concurrently without interference.
func TestPVEMultipleKEMsConcurrent(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	const numIterations = 5

	var wg sync.WaitGroup
	errors := make(chan error, numIterations*2)

	// Run HSM KEM and Toy RSA KEM operations concurrently
	for i := 0; i < numIterations; i++ {
		// HSM KEM goroutine
		wg.Add(1)
		go func(id int) {
			defer wg.Done()

			hsmKEM := testkem.NewHSMKEM(2048)
			pveInstance, err := pve.New(hsmKEM)
			if err != nil {
				errors <- fmt.Errorf("HSM %d: failed to create PVE: %v", id, err)
				return
			}

			skRef, ek, err := hsmKEM.Generate()
			if err != nil {
				errors <- fmt.Errorf("HSM %d: failed to generate keys: %v", id, err)
				return
			}

			dkHandle, err := hsmKEM.NewPrivateKeyHandle(skRef)
			if err != nil {
				errors <- fmt.Errorf("HSM %d: failed to create handle: %v", id, err)
				return
			}
			defer func() {
				_ = hsmKEM.FreePrivateKeyHandle(dkHandle)
			}()

			// Use unique value
			x, err := curve.NewScalarFromString(fmt.Sprintf("%d", id*10000+1111))
			if err != nil {
				errors <- fmt.Errorf("HSM %d: failed to create scalar: %v", id, err)
				return
			}
			defer x.Free()

			// Encrypt
			encryptResult, err := pveInstance.Encrypt(ctx, &pve.EncryptParams{
				EK:    ek,
				Label: []byte(fmt.Sprintf("hsm-%d", id)),
				Curve: cbmpc.CurveP256,
				X:     x,
			})
			if err != nil {
				errors <- fmt.Errorf("HSM %d: encrypt failed: %v", id, err)
				return
			}

			// Decrypt
			decryptResult, err := pveInstance.Decrypt(ctx, &pve.DecryptParams{
				DK:         dkHandle,
				EK:         ek,
				Ciphertext: encryptResult.Ciphertext,
				Label:      []byte(fmt.Sprintf("hsm-%d", id)),
				Curve:      cbmpc.CurveP256,
			})
			if err != nil {
				errors <- fmt.Errorf("HSM %d: decrypt failed: %v", id, err)
				return
			}
			defer decryptResult.X.Free()

			if x.String() != decryptResult.X.String() {
				errors <- fmt.Errorf("HSM %d: value mismatch: got %s, want %s",
					id, decryptResult.X.String(), x.String())
				return
			}

			fmt.Printf("HSM KEM %d: ✓ Encrypted and decrypted %s\n", id, x.String())
		}(i)

		// Toy RSA KEM goroutine
		wg.Add(1)
		go func(id int) {
			defer wg.Done()

			toyKEM := testkem.NewToyRSAKEM(2048)
			pveInstance, err := pve.New(toyKEM)
			if err != nil {
				errors <- fmt.Errorf("Toy %d: failed to create PVE: %v", id, err)
				return
			}

			skRef, ek, err := toyKEM.Generate()
			if err != nil {
				errors <- fmt.Errorf("Toy %d: failed to generate keys: %v", id, err)
				return
			}

			dkHandle, err := toyKEM.NewPrivateKeyHandle(skRef)
			if err != nil {
				errors <- fmt.Errorf("Toy %d: failed to create handle: %v", id, err)
				return
			}
			defer toyKEM.FreePrivateKeyHandle(dkHandle)

			// Use unique value
			x, err := curve.NewScalarFromString(fmt.Sprintf("%d", id*10000+2222))
			if err != nil {
				errors <- fmt.Errorf("Toy %d: failed to create scalar: %v", id, err)
				return
			}
			defer x.Free()

			// Encrypt
			encryptResult, err := pveInstance.Encrypt(ctx, &pve.EncryptParams{
				EK:    ek,
				Label: []byte(fmt.Sprintf("toy-%d", id)),
				Curve: cbmpc.CurveSecp256k1,
				X:     x,
			})
			if err != nil {
				errors <- fmt.Errorf("Toy %d: encrypt failed: %v", id, err)
				return
			}

			// Decrypt
			decryptResult, err := pveInstance.Decrypt(ctx, &pve.DecryptParams{
				DK:         dkHandle,
				EK:         ek,
				Ciphertext: encryptResult.Ciphertext,
				Label:      []byte(fmt.Sprintf("toy-%d", id)),
				Curve:      cbmpc.CurveSecp256k1,
			})
			if err != nil {
				errors <- fmt.Errorf("Toy %d: decrypt failed: %v", id, err)
				return
			}
			defer decryptResult.X.Free()

			if x.String() != decryptResult.X.String() {
				errors <- fmt.Errorf("Toy %d: value mismatch: got %s, want %s",
					id, decryptResult.X.String(), x.String())
				return
			}

			fmt.Printf("Toy RSA KEM %d: ✓ Encrypted and decrypted %s\n", id, x.String())
		}(i)
	}

	wg.Wait()
	close(errors)

	// Check for any errors
	for err := range errors {
		t.Error(err)
	}

	if t.Failed() {
		t.Fatal("Concurrent operations with multiple KEMs failed")
	}

	fmt.Println("✓ HSM KEM and Toy RSA KEM can operate concurrently!")
	fmt.Println("✓ No interference between different KEM implementations!")
}
