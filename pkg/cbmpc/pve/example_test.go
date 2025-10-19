//go:build cgo && !windows

package pve_test

import (
	"context"
	"fmt"
	"log"

	"github.com/coinbase/cb-mpc-go/pkg/cbmpc"
	"github.com/coinbase/cb-mpc-go/pkg/cbmpc/curve"
	"github.com/coinbase/cb-mpc-go/pkg/cbmpc/kem/rsa"
	"github.com/coinbase/cb-mpc-go/pkg/cbmpc/pve"
)

// Example demonstrates publicly verifiable encryption and verification.
func Example() {
	ctx := context.Background()

	// Create a deterministic RSA-OAEP KEM for PVE
	kem, err := rsa.New(2048)
	if err != nil {
		log.Fatal(err)
	}

	// Generate a KEM key pair
	skRef, ek, err := kem.Generate()
	if err != nil {
		log.Fatal(err)
	}

	// Create a handle for the private key (needed for decryption)
	dkHandle, err := kem.NewPrivateKeyHandle(skRef)
	if err != nil {
		log.Fatal(err)
	}
	defer func() {
		_ = kem.FreePrivateKeyHandle(dkHandle)
	}()

	// Create a PVE instance
	pveInstance, err := pve.New(kem)
	if err != nil {
		log.Fatal(err)
	}

	// Create a scalar to encrypt (e.g., a secret key share)
	scalar, err := curve.RandomScalar(cbmpc.CurveP256)
	if err != nil {
		log.Fatal(err)
	}
	defer scalar.Free()

	// Encrypt the scalar
	encResult, err := pveInstance.Encrypt(ctx, &pve.EncryptParams{
		EK:    ek,
		Label: []byte("backup-key-2024"),
		Curve: cbmpc.CurveP256,
		X:     scalar,
	})
	if err != nil {
		log.Fatal(err)
	}

	// Extract the public key point Q from the ciphertext
	qPoint, err := encResult.Ciphertext.Q()
	if err != nil {
		log.Fatal(err)
	}
	defer qPoint.Free()

	// Verify the ciphertext
	err = pveInstance.Verify(ctx, &pve.VerifyParams{
		EK:         ek,
		Ciphertext: encResult.Ciphertext,
		Q:          qPoint,
		Label:      []byte("backup-key-2024"),
	})
	if err != nil {
		log.Fatalf("Verification failed: %v", err)
	}

	// Decrypt the ciphertext
	decResult, err := pveInstance.Decrypt(ctx, &pve.DecryptParams{
		DK:         dkHandle,
		EK:         ek,
		Ciphertext: encResult.Ciphertext,
		Label:      []byte("backup-key-2024"),
		Curve:      cbmpc.CurveP256,
	})
	if err != nil {
		log.Fatal(err)
	}
	defer decResult.X.Free()

	// Verify the decrypted value matches the original
	originalBytes := scalar.Bytes
	decryptedBytes := decResult.X.Bytes

	fmt.Printf("Ciphertext length: %d bytes\n", len(encResult.Ciphertext))
	fmt.Printf("Verification: passed\n")
	fmt.Printf("Decryption matches original: %v\n", string(originalBytes) == string(decryptedBytes))

	// Output:
	// Ciphertext length: 433 bytes
	// Verification: passed
	// Decryption matches original: true
}

// Example_batchEncryption demonstrates encrypting multiple scalars in a single ciphertext.
func Example_batchEncryption() {
	ctx := context.Background()

	// Create KEM
	kem, err := rsa.New(2048)
	if err != nil {
		log.Fatal(err)
	}

	skRef, ek, err := kem.Generate()
	if err != nil {
		log.Fatal(err)
	}

	dkHandle, err := kem.NewPrivateKeyHandle(skRef)
	if err != nil {
		log.Fatal(err)
	}
	defer func() {
		_ = kem.FreePrivateKeyHandle(dkHandle)
	}()

	pveInstance, err := pve.New(kem)
	if err != nil {
		log.Fatal(err)
	}

	// Create multiple scalars to encrypt
	scalars := make([]*curve.Scalar, 3)
	for i := range scalars {
		s, err := curve.RandomScalar(cbmpc.CurveP256)
		if err != nil {
			log.Fatal(err)
		}
		defer s.Free()
		scalars[i] = s
	}

	// Batch encrypt
	encResult, err := pveInstance.BatchEncrypt(ctx, &pve.BatchEncryptParams{
		EK:    ek,
		Label: []byte("batch-backup"),
		Curve: cbmpc.CurveP256,
		X:     scalars,
	})
	if err != nil {
		log.Fatal(err)
	}

	// Extract Q points for verification
	qPoints := make([]*cbmpc.CurvePoint, len(scalars))
	for i, s := range scalars {
		qPoint, err := curve.MulGenerator(cbmpc.CurveP256, s)
		if err != nil {
			log.Fatal(err)
		}
		defer qPoint.Free()
		qPoints[i] = qPoint
	}

	// Batch verify
	err = pveInstance.BatchVerify(ctx, &pve.BatchVerifyParams{
		EK:         ek,
		Ciphertext: encResult.Ciphertext,
		Q:          qPoints,
		Label:      []byte("batch-backup"),
	})
	if err != nil {
		log.Fatalf("Batch verification failed: %v", err)
	}

	// Batch decrypt
	decResult, err := pveInstance.BatchDecrypt(ctx, &pve.BatchDecryptParams{
		DK:         dkHandle,
		EK:         ek,
		Ciphertext: encResult.Ciphertext,
		Label:      []byte("batch-backup"),
		Curve:      cbmpc.CurveP256,
	})
	if err != nil {
		log.Fatal(err)
	}

	for _, s := range decResult.X {
		defer s.Free()
	}

	fmt.Printf("Batch size: %d scalars\n", len(scalars))
	fmt.Printf("Batch verification: passed\n")
	fmt.Printf("Decrypted count: %d\n", len(decResult.X))

	// Output:
	// Batch size: 3 scalars
	// Batch verification: passed
	// Decrypted count: 3
}
