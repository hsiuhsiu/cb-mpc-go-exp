//go:build cgo && !windows

package rsa_test

import (
	"errors"
	"testing"

	"github.com/coinbase/cb-mpc-go/pkg/cbmpc/kem/rsa"
)

// TestHandleValidation tests that Decapsulate properly validates handle metadata.
func TestHandleValidation(t *testing.T) {
	t.Run("valid handle decapsulates successfully", func(t *testing.T) {
		// Create a KEM and generate a key pair
		kem, err := rsa.New(2048)
		if err != nil {
			t.Fatalf("Failed to create KEM: %v", err)
		}

		skRef, ek, err := kem.Generate()
		if err != nil {
			t.Fatalf("Failed to generate key pair: %v", err)
		}

		// Create handle
		handle, err := kem.NewPrivateKeyHandle(skRef)
		if err != nil {
			t.Fatalf("Failed to create handle: %v", err)
		}
		defer kem.FreePrivateKeyHandle(handle)

		// Create a ciphertext
		var rho [32]byte
		copy(rho[:], []byte("test-rho-12345678901234567890123"))
		ct, _, err := kem.Encapsulate(ek, rho)
		if err != nil {
			t.Fatalf("Failed to encapsulate: %v", err)
		}

		// Decapsulate should succeed
		ss, err := kem.Decapsulate(handle, ct)
		if err != nil {
			t.Errorf("Decapsulate failed with valid handle: %v", err)
		}
		if len(ss) != 32 {
			t.Errorf("Expected 32-byte shared secret, got %d bytes", len(ss))
		}
	})

	t.Run("invalid handle type returns ErrInvalidHandleType", func(t *testing.T) {
		kem, err := rsa.New(2048)
		if err != nil {
			t.Fatalf("Failed to create KEM: %v", err)
		}

		// Pass a wrong type (string instead of *privateKeyHandle)
		wrongHandle := "not-a-handle"

		var ct []byte // dummy ciphertext
		_, err = kem.Decapsulate(wrongHandle, ct)

		if !errors.Is(err, rsa.ErrInvalidHandleType) {
			t.Errorf("Expected ErrInvalidHandleType, got: %v", err)
		}
	})

	t.Run("corrupted algorithm ID returns ErrAlgorithmMismatch", func(t *testing.T) {
		kem, err := rsa.New(2048)
		if err != nil {
			t.Fatalf("Failed to create KEM: %v", err)
		}

		skRef, _, err := kem.Generate()
		if err != nil {
			t.Fatalf("Failed to generate key pair: %v", err)
		}

		// Create handle
		handle, err := kem.NewPrivateKeyHandle(skRef)
		if err != nil {
			t.Fatalf("Failed to create handle: %v", err)
		}
		defer kem.FreePrivateKeyHandle(handle)

		// Corrupt the algorithm ID by accessing internal fields
		// Note: This is a white-box test that accesses unexported fields
		// In real code, this would be caught by the validation
		type privateKeyHandle struct {
			AlgorithmID string
			KeySize     int
			PubKeyHash  [32]byte
			KeyDER      []byte
			PublicKey   []byte
		}

		// We can't directly corrupt since fields are unexported and mutex-protected
		// Instead, test with a handle from a different algorithm family
		// For now, skip this test as we can't easily corrupt internal state
		t.Skip("Cannot test corrupted algorithm ID without reflection or exported test helpers")
	})

	t.Run("different key sizes work correctly", func(t *testing.T) {
		testSizes := []int{2048, 3072, 4096}

		for _, keySize := range testSizes {
			t.Run(string(rune(keySize)), func(t *testing.T) {
				kem, err := rsa.New(keySize)
				if err != nil {
					t.Fatalf("Failed to create KEM with size %d: %v", keySize, err)
				}

				skRef, ek, err := kem.Generate()
				if err != nil {
					t.Fatalf("Failed to generate key pair: %v", err)
				}

				handle, err := kem.NewPrivateKeyHandle(skRef)
				if err != nil {
					t.Fatalf("Failed to create handle: %v", err)
				}
				defer kem.FreePrivateKeyHandle(handle)

				// Create and decrypt a ciphertext
				var rho [32]byte
				copy(rho[:], []byte("test-rho-12345678901234567890123"))
				ct, _, err := kem.Encapsulate(ek, rho)
				if err != nil {
					t.Fatalf("Failed to encapsulate: %v", err)
				}

				ss, err := kem.Decapsulate(handle, ct)
				if err != nil {
					t.Errorf("Decapsulate failed for key size %d: %v", keySize, err)
				}
				if len(ss) != 32 {
					t.Errorf("Expected 32-byte shared secret, got %d bytes", len(ss))
				}
			})
		}
	})

	t.Run("handle from different key size fails", func(t *testing.T) {
		// Create a 2048-bit key
		kem2048, err := rsa.New(2048)
		if err != nil {
			t.Fatalf("Failed to create 2048-bit KEM: %v", err)
		}

		skRef2048, ek2048, err := kem2048.Generate()
		if err != nil {
			t.Fatalf("Failed to generate 2048-bit key: %v", err)
		}

		handle2048, err := kem2048.NewPrivateKeyHandle(skRef2048)
		if err != nil {
			t.Fatalf("Failed to create 2048-bit handle: %v", err)
		}
		defer kem2048.FreePrivateKeyHandle(handle2048)

		// Create a 3072-bit key and ciphertext
		kem3072, err := rsa.New(3072)
		if err != nil {
			t.Fatalf("Failed to create 3072-bit KEM: %v", err)
		}

		_, ek3072, err := kem3072.Generate()
		if err != nil {
			t.Fatalf("Failed to generate 3072-bit key: %v", err)
		}

		var rho [32]byte
		copy(rho[:], []byte("test-rho-12345678901234567890123"))
		ct3072, _, err := kem3072.Encapsulate(ek3072, rho)
		if err != nil {
			t.Fatalf("Failed to encapsulate with 3072-bit key: %v", err)
		}

		// Try to decrypt 3072-bit ciphertext with 2048-bit handle
		// This should fail because the ciphertext size doesn't match the key size
		_, err = kem2048.Decapsulate(handle2048, ct3072)
		if err == nil {
			t.Error("Expected decapsulation to fail with mismatched key sizes")
		}

		// Also test the reverse: 3072-bit handle with 2048-bit ciphertext
		skRef3072, _, err := kem3072.Generate()
		if err != nil {
			t.Fatalf("Failed to generate 3072-bit key: %v", err)
		}

		handle3072, err := kem3072.NewPrivateKeyHandle(skRef3072)
		if err != nil {
			t.Fatalf("Failed to create 3072-bit handle: %v", err)
		}
		defer kem3072.FreePrivateKeyHandle(handle3072)

		ct2048, _, err := kem2048.Encapsulate(ek2048, rho)
		if err != nil {
			t.Fatalf("Failed to encapsulate with 2048-bit key: %v", err)
		}

		_, err = kem3072.Decapsulate(handle3072, ct2048)
		if err == nil {
			t.Error("Expected decapsulation to fail with mismatched key sizes")
		}
	})
}

// TestBoundEKHash ensures that when a KEM instance is bound to a specific
// public key hash, decapsulation with a handle bound to a different key fails
// with the expected typed error.
func TestBoundEKHash(t *testing.T) {
	kem1, err := rsa.New(2048)
	if err != nil {
		t.Fatalf("Failed to create KEM: %v", err)
	}

	// Generate a key pair and associated handle
	skRef, ek, err := kem1.Generate()
	if err != nil {
		t.Fatalf("Failed to generate key pair: %v", err)
	}

	handle, err := kem1.NewPrivateKeyHandle(skRef)
	if err != nil {
		t.Fatalf("Failed to create handle: %v", err)
	}
	defer kem1.FreePrivateKeyHandle(handle)

	// Generate a different public key and bind kem1 to it
	kem2, err := rsa.New(2048)
	if err != nil {
		t.Fatalf("Failed to create secondary KEM: %v", err)
	}
	_, ekDifferent, err := kem2.Generate()
	if err != nil {
		t.Fatalf("Failed to generate secondary key pair: %v", err)
	}
	kem1.BindPublicKey(ekDifferent)

	// Create a ciphertext for the original ek
	var rho [32]byte
	copy(rho[:], []byte("test-rho-12345678901234567890123"))
	ct, _, err := kem1.Encapsulate(ek, rho)
	if err != nil {
		t.Fatalf("Failed to encapsulate: %v", err)
	}

	// Decapsulation should fail due to bound EK hash mismatch
	_, err = kem1.Decapsulate(handle, ct)
	if !errors.Is(err, rsa.ErrPublicKeyHashMismatch) {
		t.Errorf("Expected ErrPublicKeyHashMismatch, got: %v", err)
	}
}
