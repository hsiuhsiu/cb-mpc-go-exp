# KEM Determinism Example

This example demonstrates the deterministic property of the RSA-OAEP KEM used in PVE.

## What it shows

- Same `(public_key, rho)` produces **identical ciphertexts** (byte-for-byte)
- This deterministic property is **essential for PVE** (Publicly Verifiable Encryption)
- **Not suitable** for general-purpose encryption

## Running

```bash
# From repository root
go run examples/kem-determinism/main.go
```

## Expected Output

```
=== KEM Determinism Example ===

Step 1: Creating RSA KEM (2048-bit)...
✓ KEM created

Step 2: Generating key pair...
✓ Key pair generated (public key: 294 bytes)

Step 3: Using fixed seed (rho): "deterministic-seed-1234567890123"

Step 4: Encrypting twice with same (ek, rho)...
  First encryption:  ct=256 bytes, ss=32 bytes
  Second encryption: ct=256 bytes, ss=32 bytes

Step 5: Verifying determinism...
✓ SUCCESS: Ciphertexts are IDENTICAL (byte-for-byte)
  This is the deterministic property required for PVE.
✓ SUCCESS: Shared secrets are identical

=== Determinism Example Complete ===

Summary:
  ✓ Same (ek, rho) produces identical ciphertext
  ✓ This deterministic property is essential for PVE
  ⚠️  NEVER use this for general-purpose encryption!
```

## Supported Platforms

- ✅ macOS (Intel and Apple Silicon)
- ✅ Linux (amd64 and arm64)
- ❌ Windows (unsupported)

## See Also

- `pkg/cbmpc/kem/README.md` - Full KEM package documentation
- `examples/kem-pve-roundtrip/` - Complete PVE round-trip example
- `examples/pve/` - Full PVE protocol example
