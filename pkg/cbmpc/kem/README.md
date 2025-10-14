# KEM Package - Deterministic RSA-OAEP for PVE

**Deterministic RSA-OAEP for PVE; not a general randomized KEM.**

**Supported platforms:** macOS & Linux only. Windows unsupported.

---

**CRITICAL SECURITY WARNING**

## This is NOT a General-Purpose KEM!

**All KEM implementations in this package are DETERMINISTIC and designed exclusively for Publicly Verifiable Encryption (PVE).**

### What This Means

- **DETERMINISTIC**: Same (public_key, rho) → same ciphertext
- **PVE-SPECIFIC**: Only safe within the PVE protocol context
- **NOT RANDOMIZED**: Does not use random bytes for encryption
- **UNSAFE** for general public-key encryption use cases

---

## Quick Start

### Demonstrating Determinism

```go
package main

import (
    "bytes"
    "fmt"
    "log"

    "github.com/coinbase/cb-mpc-go/pkg/cbmpc/kem/rsa"
)

func main() {
    // Create a KEM
    kem, err := rsa.New(2048)
    if err != nil {
        log.Fatal(err)
    }

    // Generate key pair
    _, ek, err := kem.Generate()
    if err != nil {
        log.Fatal(err)
    }

    // Fixed rho (seed)
    var rho [32]byte
    copy(rho[:], []byte("deterministic-seed-1234567890123"))

    // Encrypt twice with same (ek, rho)
    ct1, _, err := kem.Encapsulate(ek, rho)
    if err != nil {
        log.Fatal(err)
    }

    ct2, _, err := kem.Encapsulate(ek, rho)
    if err != nil {
        log.Fatal(err)
    }

    // Ciphertexts are IDENTICAL (byte-for-byte)
    if bytes.Equal(ct1, ct2) {
        fmt.Println("✓ Determinism verified: same (ek, rho) → identical ciphertext")
    } else {
        fmt.Println("✗ FAIL: Ciphertexts differ!")
    }
}
```

### PVE Round-Trip

```go
package main

import (
    "context"
    "fmt"
    "log"
    "time"

    "github.com/coinbase/cb-mpc-go/pkg/cbmpc"
    "github.com/coinbase/cb-mpc-go/pkg/cbmpc/curve"
    "github.com/coinbase/cb-mpc-go/pkg/cbmpc/kem/rsa"
    "github.com/coinbase/cb-mpc-go/pkg/cbmpc/pve"
)

func main() {
    ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
    defer cancel()

    // 1. Create KEM
    kem, err := rsa.New(2048)
    if err != nil {
        log.Fatal(err)
    }

    // 2. Generate key pair
    skRef, ek, err := kem.Generate()
    if err != nil {
        log.Fatal(err)
    }

    // 3. Create private key handle
    dkHandle, err := kem.NewPrivateKeyHandle(skRef)
    if err != nil {
        log.Fatal(err)
    }
    defer kem.FreePrivateKeyHandle(dkHandle)

    // 4. Create PVE instance
    pveInstance, err := pve.New(kem)
    if err != nil {
        log.Fatal(err)
    }

    // 5. Encrypt a scalar value
    secretValue := "123456789012345678901234567890"
    x, err := curve.NewScalarFromString(secretValue)
    if err != nil {
        log.Fatal(err)
    }
    defer x.Free()

    label := []byte("my-label")
    encryptResult, err := pveInstance.Encrypt(ctx, &pve.EncryptParams{
        EK:    ek,
        Label: label,
        Curve: cbmpc.CurveP256,
        X:     x,
    })
    if err != nil {
        log.Fatal(err)
    }

    // 6. Extract Q for verification
    Q, err := encryptResult.Ciphertext.Q()
    if err != nil {
        log.Fatal(err)
    }
    defer Q.Free()

    // 7. Verify ciphertext (publicly verifiable proof)
    err = pveInstance.Verify(ctx, &pve.VerifyParams{
        EK:         ek,
        Ciphertext: encryptResult.Ciphertext,
        Q:          Q,
        Label:      label,
    })
    if err != nil {
        log.Fatalf("Verification failed: %v", err)
    }
    fmt.Println("✓ Ciphertext verified")

    // 8. Decrypt
    decryptResult, err := pveInstance.Decrypt(ctx, &pve.DecryptParams{
        DK:         dkHandle,
        EK:         ek,
        Ciphertext: encryptResult.Ciphertext,
        Label:      label,
        Curve:      cbmpc.CurveP256,
    })
    if err != nil {
        log.Fatal(err)
    }
    defer decryptResult.X.Free()

    if secretValue == decryptResult.X.String() {
        fmt.Println("✓ PVE round-trip successful")
    } else {
        log.Fatal("✗ Decrypted value doesn't match!")
    }
}
```

Run either example on macOS or Linux:
```bash
go run main.go
```

---

## Why Determinism?

Traditional randomized public-key encryption (like standard RSA-OAEP) uses fresh random bytes for each encryption. This ensures that encrypting the same message twice produces different ciphertexts, which is critical for semantic security (IND-CCA2).

However, **Publicly Verifiable Encryption (PVE)** requires a different property: anyone should be able to verify that a ciphertext was correctly generated without seeing the plaintext or private key.

### The PVE Construction

PVE uses a **Fiat-Shamir-style** non-interactive proof:

1. **Commit to the secret**: Compute `Q = x·G` (elliptic curve point)
2. **Deterministic encryption**: Encrypt using `rho = Hash(Q, label, ...)` as the seed
3. **Zero-knowledge proof**: Prove knowledge of `x` such that `Q = x·G` and ciphertext matches

The deterministic property is **essential** because:
- The verifier must be able to recompute the ciphertext using `Q` and `label`
- If encryption were randomized, the verifier couldn't reproduce it
- Determinism binds the ciphertext to the commitment `Q`

### Domain Separation

To prevent cross-key attacks with deterministic encryption, this implementation provides **domain separation**:

```
ekHash = SHA-256(ek)
label = "cbmpc/pve/rsa-oaep:" || ekHash
seed = SHA-256(rho || ekHash)
ciphertext = RSA-OAEP(ek, ss, label, seed)
```

This ensures:
- Same `rho` with **different keys** produces **different ciphertexts**
- Ciphertexts are cryptographically bound to specific public keys
- Decryption requires the matching public key (via label check)

### References

- **Fiat-Shamir heuristic**: Converting interactive proofs to non-interactive
- **PVE Protocol**: See `pkg/cbmpc/pve` package documentation
- **Domain Separation**: Security fix for deterministic OAEP binding

---

## DO NOT Use This For

- General-purpose public-key encryption
- Applications requiring IND-CCA2 security
- Any scenario where `rho` might be reused
- Encrypting multiple messages with the same seed
- Standard PKI/TLS applications
- File encryption, email encryption, etc.

## Safe Use Cases

**ONLY** use within the PVE (Publicly Verifiable Encryption) protocol where:

1. **Fresh rho per encryption**: Each encryption uses a unique, unpredictable 32-byte seed
2. **PVE protocol context**: Used as part of the full PVE protocol (not standalone)
3. **Determinism is required**: Verifiability properties depend on deterministic behavior
4. **Security model is understood**: Caller understands the security implications

---

## Platform Support

| Platform | Support | Notes |
|----------|---------|-------|
| **macOS** | ✅ Supported | Intel and Apple Silicon |
| **Linux** | ✅ Supported | amd64 and arm64 |
| **Windows** | ❌ Unsupported | Build tags exclude Windows |

The package uses `//go:build cgo && !windows` to exclude Windows builds. Attempting to use this package on Windows will result in stub implementations that return `ErrNotBuilt`.

---

## Security Properties

### Domain Separation

Implementations provide domain separation to prevent cross-key attacks:

- **Key-bound OAEP label**: Each public key has a unique label (`cbmpc/pve/rsa-oaep:SHA256(ek)`)
- **Key-bound seed derivation**: Deterministic seed includes hash of public key
- **Cross-key security**: Same `rho` with different keys produces different ciphertexts

### Cryptographic Binding

```
ekHash = SHA-256(ek)
label = "cbmpc/pve/rsa-oaep:" || ekHash
seed = SHA-256(rho || ekHash)
ciphertext = RSA-OAEP(ek, ss, label, seed)
```

This ensures:
- Ciphertexts are bound to specific public keys
- Same `rho` cannot leak information across different keys
- Decryption requires matching public key (via label check)

### Handle Metadata and Runtime Checks

To reduce misuse risk with `any` decapsulation handles, the built-in RSA private key handle stores:

- Algorithm ID (e.g., `rsa-oaep-2048`)
- Modulus size in bytes
- Public key hash `SHA-256(ek)`

At decapsulation time, the RSA KEM verifies:

- Algorithm family is RSA-OAEP
- Modulus size is one of 2048/3072/4096 bits and matches this KEM's configured size
- Public key hash in the handle matches the actual handle public key
- Optional: if the KEM instance is bound to a specific public key hash, it must match

Typed errors are returned on mismatch (no panics):

- `rsa.ErrInvalidHandleType`
- `rsa.ErrAlgorithmMismatch`
- `rsa.ErrUnsupportedKeySize`
- `rsa.ErrPublicKeyHashMismatch`

---

## Implementation: RSA-OAEP

The `rsa` package provides deterministic RSA-OAEP encryption:

### Key Sizes

- **2048 bits**: Minimum for current use
- **3072 bits**: Recommended for long-term security (post-2030)
- **4096 bits**: High-security applications

### Security Features

- SHA-256 for all hashing operations
- PKCS#8 DER format for private keys
- Secure key zeroization on free
- Key-bound OAEP labels for domain separation
- Deterministic seed derivation with key binding

---

## Security Auditing

When reviewing code that uses this package:

### Good Practices

- KEM only used via `pve.New(kem)`
- Fresh `rho` generated for each PVE encryption
- `rho` derived from cryptographically secure source
- KEM instances not shared across different security contexts

### Red Flags

- Direct calls to `kem.Encapsulate()` outside PVE
- Reusing `rho` values across multiple encryptions
- Using same `rho` for different messages
- Comments mentioning "general-purpose" or "randomized" KEM
- KEM used for non-PVE encryption

---

## Questions?

If you're unsure whether your use case is appropriate:

**Don't use this package.** Use a standard randomized KEM instead.

If you need deterministic encryption for PVE and understand the security implications, ensure:

1. You're implementing or using the full PVE protocol
2. Each encryption uses a fresh, unpredictable `rho`
3. You understand why determinism is safe in your specific context
4. You've reviewed the security properties and constraints
