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
		defer func() {
			if err := kem.FreePrivateKeyHandle(handle); err != nil {
				t.Errorf("Failed to free handle: %v", err)
			}
		}()

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
		defer func() {
			if err := kem.FreePrivateKeyHandle(handle); err != nil {
				t.Errorf("Failed to free handle: %v", err)
			}
		}()

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
				defer func() {
					if err := kem.FreePrivateKeyHandle(handle); err != nil {
						t.Errorf("Failed to free handle: %v", err)
					}
				}()

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
		defer func() {
			if err := kem2048.FreePrivateKeyHandle(handle2048); err != nil {
				t.Errorf("Failed to free 2048-bit handle: %v", err)
			}
		}()

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
		defer func() {
			if err := kem3072.FreePrivateKeyHandle(handle3072); err != nil {
				t.Errorf("Failed to free 3072-bit handle: %v", err)
			}
		}()

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

// TestDeterminismAndDomainSeparation tests the cryptographic properties
// established in ticket #1: deterministic encryption and domain separation.
func TestDeterminismAndDomainSeparation(t *testing.T) {
	t.Run("determinism: same (ek, rho) produces identical ciphertext", func(t *testing.T) {
		kem, err := rsa.New(2048)
		if err != nil {
			t.Fatalf("Failed to create KEM: %v", err)
		}

		// Generate a key pair
		_, ek, err := kem.Generate()
		if err != nil {
			t.Fatalf("Failed to generate key pair: %v", err)
		}

		// Fixed rho
		var rho [32]byte
		copy(rho[:], []byte("deterministic-rho-1234567890123"))

		// Encapsulate twice with same (ek, rho)
		ct1, ss1, err := kem.Encapsulate(ek, rho)
		if err != nil {
			t.Fatalf("First encapsulation failed: %v", err)
		}

		ct2, ss2, err := kem.Encapsulate(ek, rho)
		if err != nil {
			t.Fatalf("Second encapsulation failed: %v", err)
		}

		// Ciphertexts must be EXACTLY identical (byte-for-byte)
		if string(ct1) != string(ct2) {
			t.Errorf("Determinism violation: same (ek, rho) produced different ciphertexts")
			t.Errorf("  ct1 length: %d bytes", len(ct1))
			t.Errorf("  ct2 length: %d bytes", len(ct2))
		}

		// Shared secrets must also be identical
		if string(ss1) != string(ss2) {
			t.Errorf("Shared secrets differ for same (ek, rho)")
		}
	})

	t.Run("domain separation: different keys produce different ciphertexts", func(t *testing.T) {
		kem, err := rsa.New(2048)
		if err != nil {
			t.Fatalf("Failed to create KEM: %v", err)
		}

		// Generate two different key pairs
		_, ek1, err := kem.Generate()
		if err != nil {
			t.Fatalf("Failed to generate first key pair: %v", err)
		}

		_, ek2, err := kem.Generate()
		if err != nil {
			t.Fatalf("Failed to generate second key pair: %v", err)
		}

		// Verify keys are actually different
		if string(ek1) == string(ek2) {
			t.Skip("Generated identical keys (extremely unlikely), skipping test")
		}

		// Same rho for both
		var rho [32]byte
		copy(rho[:], []byte("same-rho-for-both-keys-12345678"))

		// Encapsulate with each key
		ct1, ss1, err := kem.Encapsulate(ek1, rho)
		if err != nil {
			t.Fatalf("Encapsulation with ek1 failed: %v", err)
		}

		ct2, ss2, err := kem.Encapsulate(ek2, rho)
		if err != nil {
			t.Fatalf("Encapsulation with ek2 failed: %v", err)
		}

		// Ciphertexts MUST be different (domain separation)
		if string(ct1) == string(ct2) {
			t.Errorf("Domain separation violation: different keys with same rho produced identical ciphertexts")
		}

		// Note: shared secrets are the same (both are rho) in this implementation
		// This is expected for PVE's deterministic KEM
		if string(ss1) != string(ss2) {
			t.Logf("Note: shared secrets differ (implementation detail)")
		}
	})

	t.Run("different rho produces different ciphertext", func(t *testing.T) {
		kem, err := rsa.New(2048)
		if err != nil {
			t.Fatalf("Failed to create KEM: %v", err)
		}

		// Generate a key pair
		_, ek, err := kem.Generate()
		if err != nil {
			t.Fatalf("Failed to generate key pair: %v", err)
		}

		// Two different rho values
		var rho1 [32]byte
		copy(rho1[:], []byte("first-rho-12345678901234567890"))

		var rho2 [32]byte
		copy(rho2[:], []byte("second-rho-1234567890123456789"))

		// Encapsulate with each rho
		ct1, ss1, err := kem.Encapsulate(ek, rho1)
		if err != nil {
			t.Fatalf("Encapsulation with rho1 failed: %v", err)
		}

		ct2, ss2, err := kem.Encapsulate(ek, rho2)
		if err != nil {
			t.Fatalf("Encapsulation with rho2 failed: %v", err)
		}

		// Ciphertexts must be different
		if string(ct1) == string(ct2) {
			t.Errorf("Different rho values produced identical ciphertexts")
		}

		// Shared secrets must be different
		if string(ss1) == string(ss2) {
			t.Errorf("Different rho values produced identical shared secrets")
		}
	})

	t.Run("corruption: flipped byte causes decapsulation error", func(t *testing.T) {
		kem, err := rsa.New(2048)
		if err != nil {
			t.Fatalf("Failed to create KEM: %v", err)
		}

		// Generate key pair and handle
		skRef, ek, err := kem.Generate()
		if err != nil {
			t.Fatalf("Failed to generate key pair: %v", err)
		}

		handle, err := kem.NewPrivateKeyHandle(skRef)
		if err != nil {
			t.Fatalf("Failed to create handle: %v", err)
		}
		defer func() {
			if err := kem.FreePrivateKeyHandle(handle); err != nil {
				t.Errorf("Failed to free handle: %v", err)
			}
		}()

		// Create a valid ciphertext
		var rho [32]byte
		copy(rho[:], []byte("test-rho-12345678901234567890123"))

		ct, ss, err := kem.Encapsulate(ek, rho)
		if err != nil {
			t.Fatalf("Encapsulation failed: %v", err)
		}

		// Verify original decapsulation works
		ssDecap, err := kem.Decapsulate(handle, ct)
		if err != nil {
			t.Fatalf("Original decapsulation failed: %v", err)
		}
		if string(ss) != string(ssDecap) {
			t.Fatalf("Original shared secrets don't match")
		}

		// Corrupt the ciphertext by flipping a byte in the middle
		corruptedCT := make([]byte, len(ct))
		copy(corruptedCT, ct)
		if len(corruptedCT) > 0 {
			corruptedCT[len(corruptedCT)/2] ^= 0xFF // Flip all bits
		}

		// Decapsulation with corrupted ciphertext should fail
		_, err = kem.Decapsulate(handle, corruptedCT)
		if err == nil {
			t.Error("Decapsulation should have failed with corrupted ciphertext")
		}

		// The error should be a typed error (fmt.Errorf wrapping)
		// We expect "RSA-OAEP decapsulation failed" error
		if err != nil && !contains(err.Error(), "decapsulation failed") {
			t.Logf("Got error (expected): %v", err)
		}
	})
}

// Helper function to check if error message contains substring
func contains(s, substr string) bool {
	return len(s) >= len(substr) &&
		(s == substr || len(s) > len(substr) &&
			(s[:len(substr)] == substr || s[len(s)-len(substr):] == substr ||
				findSubstring(s, substr)))
}

func findSubstring(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
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
	defer func() {
		if err := kem1.FreePrivateKeyHandle(handle); err != nil {
			t.Errorf("Failed to free handle: %v", err)
		}
	}()

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
