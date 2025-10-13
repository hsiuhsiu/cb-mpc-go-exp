# KEM Package - Deterministic Key Encapsulation for PVE

**CRITICAL SECURITY WARNING**

## This is NOT a General-Purpose KEM!

**All KEM implementations in this package are DETERMINISTIC and designed exclusively for Publicly Verifiable Encryption (PVE).**

### What This Means

- **DETERMINISTIC**: Same (public_key, rho) → same ciphertext
- **PVE-SPECIFIC**: Only safe within the PVE protocol context
- **NOT RANDOMIZED**: Does not use random bytes for encryption
- **UNSAFE** for general public-key encryption use cases

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

## Usage Example

```go
import (
    "github.com/coinbase/cb-mpc-go/pkg/cbmpc/kem/rsa"
    "github.com/coinbase/cb-mpc-go/pkg/cbmpc/pve"
)

// Create a KEM (deterministic RSA-OAEP)
kem, err := rsa.New(2048)
if err != nil {
    log.Fatal(err)
}

// Generate key pair
skRef, ek, err := kem.Generate()
if err != nil {
    log.Fatal(err)
}

// Create PVE instance with this KEM
// NOTE: KEM is only used within PVE context!
pveInstance, err := pve.New(kem)
if err != nil {
    log.Fatal(err)
}

// Use PVE (which internally uses the deterministic KEM correctly)
// DO NOT call kem.Encapsulate() directly unless you fully understand
// the security implications!
```

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

## References

- PVE Protocol: See `pkg/cbmpc/pve` package documentation
- RSA-OAEP: PKCS #1 v2.2 (RFC 8017)
- Domain Separation: Security fix for deterministic OAEP binding

## Questions?

If you're unsure whether your use case is appropriate:

**Don't use this package.** Use a standard randomized KEM instead.

If you need deterministic encryption for PVE and understand the security implications, ensure:

1. You're implementing or using the full PVE protocol
2. Each encryption uses a fresh, unpredictable `rho`
3. You understand why determinism is safe in your specific context
4. You've reviewed the security properties and constraints
