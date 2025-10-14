# KEM PVE Round-Trip Example

This example demonstrates a complete PVE (Publicly Verifiable Encryption) round-trip using the deterministic RSA-OAEP KEM.

## What it shows

1. **KEM setup**: Create deterministic RSA-OAEP KEM and generate key pair
2. **PVE encryption**: Encrypt a scalar value with PVE
3. **Public verification**: Verify ciphertext correctness (without private key!)
4. **PVE decryption**: Decrypt and recover original value
5. **Proper cleanup**: Zeroize sensitive data

## Running

```bash
# From repository root (after make build-cbmpc)
go run examples/kem-pve-roundtrip/main.go
```

## Expected Output

```
=== PVE Round-Trip Example ===

Step 1: Creating RSA KEM (2048-bit)...
✓ KEM created

Step 2: Generating key pair...
✓ Key pair generated (public key: 294 bytes, private key ref: 1218 bytes)

Step 3: Creating private key handle...
✓ Private key handle created

Step 4: Creating PVE instance...
✓ PVE instance created

Step 5: Encrypting secret value...
  Secret: 123456789012345678901234567890
  Label:  my-label
✓ Encryption successful (ciphertext: XXX bytes)

Step 6: Extracting public commitment Q...
✓ Q extracted (XX bytes, curve: P-256)

Step 7: Verifying ciphertext (publicly verifiable proof)...
✓ Ciphertext verified - proof of correct encryption!

Step 8: Decrypting ciphertext...
✓ Decryption successful
  Original:  123456789012345678901234567890
  Decrypted: 123456789012345678901234567890
✓ Values match!

Step 9: Cleanup...
✓ Sensitive data zeroized

=== PVE Round-Trip Complete ===

Summary:
  ✓ Successfully encrypted data with PVE
  ✓ Successfully verified ciphertext (proof of correct encryption)
  ✓ Successfully decrypted ciphertext
  ✓ Original and decrypted values match
  ✓ Deterministic RSA KEM (2048-bit) used throughout
```

## Supported Platforms

- ✅ macOS (Intel and Apple Silicon)
- ✅ Linux (amd64 and arm64)
- ❌ Windows (unsupported)

## See Also

- `pkg/cbmpc/kem/README.md` - Full KEM package documentation
- `examples/kem-determinism/` - Simpler determinism-only example
- `examples/pve/` - Full-featured PVE example with more test cases
