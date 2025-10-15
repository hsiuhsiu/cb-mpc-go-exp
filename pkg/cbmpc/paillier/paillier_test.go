//go:build cgo && !windows

package paillier_test

import (
	"testing"

	"github.com/coinbase/cb-mpc-go/pkg/cbmpc/paillier"
)

func TestPaillierGenerate(t *testing.T) {
	p, err := paillier.Generate()
	if err != nil {
		t.Fatalf("Generate failed: %v", err)
	}
	defer p.Close()

	if !p.HasPrivateKey() {
		t.Error("Generated Paillier key should have private key")
	}

	// Verify we can get the modulus
	n, err := p.GetN()
	if err != nil {
		t.Fatalf("GetN failed: %v", err)
	}
	if len(n) == 0 {
		t.Error("Modulus N should not be empty")
	}
	// 2048-bit modulus should be 256 bytes
	if len(n) != 256 {
		t.Errorf("Expected 256-byte modulus, got %d bytes", len(n))
	}
}

func TestPaillierFromPublicKey(t *testing.T) {
	// First generate a keypair to get N
	p1, err := paillier.Generate()
	if err != nil {
		t.Fatalf("Generate failed: %v", err)
	}
	defer p1.Close()

	n, err := p1.GetN()
	if err != nil {
		t.Fatalf("GetN failed: %v", err)
	}

	// Create from public key only
	p2, err := paillier.FromPublicKey(n)
	if err != nil {
		t.Fatalf("FromPublicKey failed: %v", err)
	}
	defer p2.Close()

	if p2.HasPrivateKey() {
		t.Error("Public key only instance should not have private key")
	}

	// Verify we can get the same modulus
	n2, err := p2.GetN()
	if err != nil {
		t.Fatalf("GetN failed: %v", err)
	}
	if len(n) != len(n2) {
		t.Errorf("Modulus length mismatch: %d vs %d", len(n), len(n2))
	}
}

func TestPaillierEncryptDecrypt(t *testing.T) {
	p, err := paillier.Generate()
	if err != nil {
		t.Fatalf("Generate failed: %v", err)
	}
	defer p.Close()

	// Create a simple plaintext (small number)
	plaintext := []byte{0x42}

	// Encrypt
	ciphertext, err := p.Encrypt(plaintext)
	if err != nil {
		t.Fatalf("Encrypt failed: %v", err)
	}
	if len(ciphertext) == 0 {
		t.Error("Ciphertext should not be empty")
	}

	// Decrypt
	decrypted, err := p.Decrypt(ciphertext)
	if err != nil {
		t.Fatalf("Decrypt failed: %v", err)
	}

	// Verify plaintext matches (may have leading zeros)
	if len(decrypted) == 0 {
		t.Error("Decrypted plaintext should not be empty")
	}
	// Find the first non-zero byte
	start := 0
	for start < len(decrypted) && decrypted[start] == 0 {
		start++
	}
	if start >= len(decrypted) {
		t.Error("Decrypted plaintext is all zeros")
	} else if decrypted[start] != 0x42 {
		t.Errorf("Decrypted plaintext mismatch: expected 0x42, got 0x%x", decrypted[start])
	}
}

func TestPaillierAddCiphers(t *testing.T) {
	p, err := paillier.Generate()
	if err != nil {
		t.Fatalf("Generate failed: %v", err)
	}
	defer p.Close()

	// Create two plaintexts
	plaintext1 := []byte{0x03}
	plaintext2 := []byte{0x05}

	// Encrypt both
	c1, err := p.Encrypt(plaintext1)
	if err != nil {
		t.Fatalf("Encrypt failed: %v", err)
	}
	c2, err := p.Encrypt(plaintext2)
	if err != nil {
		t.Fatalf("Encrypt failed: %v", err)
	}

	// Homomorphically add
	cSum, err := p.AddCiphers(c1, c2)
	if err != nil {
		t.Fatalf("AddCiphers failed: %v", err)
	}

	// Decrypt sum
	decrypted, err := p.Decrypt(cSum)
	if err != nil {
		t.Fatalf("Decrypt failed: %v", err)
	}

	// Verify result is 0x03 + 0x05 = 0x08
	start := 0
	for start < len(decrypted) && decrypted[start] == 0 {
		start++
	}
	if start >= len(decrypted) {
		t.Error("Decrypted sum is all zeros")
	} else if decrypted[start] != 0x08 {
		t.Errorf("Decrypted sum mismatch: expected 0x08, got 0x%x", decrypted[start])
	}
}

func TestPaillierMulScalar(t *testing.T) {
	p, err := paillier.Generate()
	if err != nil {
		t.Fatalf("Generate failed: %v", err)
	}
	defer p.Close()

	// Create a plaintext
	plaintext := []byte{0x03}
	scalar := []byte{0x05}

	// Encrypt
	c, err := p.Encrypt(plaintext)
	if err != nil {
		t.Fatalf("Encrypt failed: %v", err)
	}

	// Homomorphically multiply by scalar
	cProduct, err := p.MulScalar(c, scalar)
	if err != nil {
		t.Fatalf("MulScalar failed: %v", err)
	}

	// Decrypt product
	decrypted, err := p.Decrypt(cProduct)
	if err != nil {
		t.Fatalf("Decrypt failed: %v", err)
	}

	// Verify result is 0x03 * 0x05 = 0x0f
	start := 0
	for start < len(decrypted) && decrypted[start] == 0 {
		start++
	}
	if start >= len(decrypted) {
		t.Error("Decrypted product is all zeros")
	} else if decrypted[start] != 0x0f {
		t.Errorf("Decrypted product mismatch: expected 0x0f, got 0x%x", decrypted[start])
	}
}

func TestPaillierVerifyCipher(t *testing.T) {
	p, err := paillier.Generate()
	if err != nil {
		t.Fatalf("Generate failed: %v", err)
	}
	defer p.Close()

	// Create a valid ciphertext
	plaintext := []byte{0x42}
	ciphertext, err := p.Encrypt(plaintext)
	if err != nil {
		t.Fatalf("Encrypt failed: %v", err)
	}

	// Verify it
	err = p.VerifyCipher(ciphertext)
	if err != nil {
		t.Errorf("VerifyCipher failed for valid ciphertext: %v", err)
	}

	// Try with invalid ciphertext (all zeros - unlikely to be valid)
	invalidCiphertext := make([]byte, len(ciphertext))
	err = p.VerifyCipher(invalidCiphertext)
	if err == nil {
		t.Error("VerifyCipher should fail for invalid ciphertext")
	}
}

func TestPaillierSerializeDeserialize(t *testing.T) {
	// Generate a keypair
	p1, err := paillier.Generate()
	if err != nil {
		t.Fatalf("Generate failed: %v", err)
	}
	defer p1.Close()

	// Serialize
	serialized, err := p1.Serialize()
	if err != nil {
		t.Fatalf("Serialize failed: %v", err)
	}
	if len(serialized) == 0 {
		t.Error("Serialized data should not be empty")
	}

	// Deserialize
	p2, err := paillier.Deserialize(serialized)
	if err != nil {
		t.Fatalf("Deserialize failed: %v", err)
	}
	defer p2.Close()

	// Verify both have private key
	if !p1.HasPrivateKey() {
		t.Error("Original should have private key")
	}
	if !p2.HasPrivateKey() {
		t.Error("Deserialized should have private key")
	}

	// Verify moduli match
	n1, err := p1.GetN()
	if err != nil {
		t.Fatalf("GetN failed: %v", err)
	}
	n2, err := p2.GetN()
	if err != nil {
		t.Fatalf("GetN failed: %v", err)
	}
	if len(n1) != len(n2) {
		t.Errorf("Modulus length mismatch: %d vs %d", len(n1), len(n2))
	}

	// Verify encryption/decryption works with both
	plaintext := []byte{0x42}
	c1, err := p1.Encrypt(plaintext)
	if err != nil {
		t.Fatalf("Encrypt with p1 failed: %v", err)
	}
	// Decrypt with p2 (deserialized key)
	decrypted, err := p2.Decrypt(c1)
	if err != nil {
		t.Fatalf("Decrypt with p2 failed: %v", err)
	}
	// Verify plaintext matches
	start := 0
	for start < len(decrypted) && decrypted[start] == 0 {
		start++
	}
	if start >= len(decrypted) || decrypted[start] != 0x42 {
		t.Error("Cross-key encryption/decryption failed")
	}
}

func TestPaillierPublicKeyCannotDecrypt(t *testing.T) {
	// Generate a keypair to get N
	p1, err := paillier.Generate()
	if err != nil {
		t.Fatalf("Generate failed: %v", err)
	}
	defer p1.Close()

	n, err := p1.GetN()
	if err != nil {
		t.Fatalf("GetN failed: %v", err)
	}

	// Create from public key only
	p2, err := paillier.FromPublicKey(n)
	if err != nil {
		t.Fatalf("FromPublicKey failed: %v", err)
	}
	defer p2.Close()

	// Encrypt with full key
	plaintext := []byte{0x42}
	ciphertext, err := p1.Encrypt(plaintext)
	if err != nil {
		t.Fatalf("Encrypt failed: %v", err)
	}

	// Try to decrypt with public key only - should fail
	_, err = p2.Decrypt(ciphertext)
	if err == nil {
		t.Error("Decrypt should fail with public key only")
	}
}

func TestPaillierClose(t *testing.T) {
	p, err := paillier.Generate()
	if err != nil {
		t.Fatalf("Generate failed: %v", err)
	}

	// Close it
	p.Close()

	// Verify operations fail after close
	_, err = p.GetN()
	if err == nil {
		t.Error("GetN should fail after Close")
	}

	_, err = p.Encrypt([]byte{0x42})
	if err == nil {
		t.Error("Encrypt should fail after Close")
	}

	// Close again should be safe
	p.Close()
}
