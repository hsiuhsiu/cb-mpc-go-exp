# PVE (Publicly Verifiable Encryption) Example

This example demonstrates how to use Publicly Verifiable Encryption (PVE) with a deterministic RSA KEM.

## What is PVE?

PVE (Publicly Verifiable Encryption) allows:
- **Encryption**: Encrypt a secret value with a public key
- **Public Verification**: Anyone can verify the ciphertext is correctly formed (without decrypting)
- **Decryption**: Only the holder of the private key can decrypt

This is useful for protocols where you need to prove that an encryption was performed correctly without revealing the plaintext.

## Features Demonstrated

This example shows:

1. **PVE Encryption** - Encrypting a secret scalar value
2. **PVE Verification** - Verifying the ciphertext is correct (publicly verifiable proof)
3. **Verification Failure Detection** - Detecting tampered ciphertexts or wrong parameters
4. **PVE Decryption** - Recovering the original value
5. **Decryption Failure Detection** - Detecting wrong ciphertexts or parameters
6. **Long-Term Security** - Using 3072-bit RSA KEM (recommended for security beyond 2030)

## Running the Example

```bash
# From repository root
go run examples/pve/main.go
```

## Expected Output

```
=== PVE (Publicly Verifiable Encryption) Example ===

Step 1: Creating RSA KEM (3072-bit)...
✓ RSA KEM created

Step 2: Generating RSA key pair...
✓ Key pair generated (public key: 422 bytes, private key ref: 1854 bytes)

Step 3: Creating private key handle...
✓ Private key handle created

Step 4: Creating PVE instance...
✓ PVE instance created

Step 5: Preparing data to encrypt...
  Label: transaction-signature-2025-10-09
  Secret value: 123456789012345678901234567890
✓ Data prepared

Step 6: Encrypting with PVE...
✓ Encryption successful (ciphertext: XXX bytes)

Step 7: Extracting public commitment Q...
✓ Q extracted (XX bytes)

Step 8: Verifying ciphertext...
✓ Verification successful - ciphertext is valid!

Step 9: Testing verification with wrong label (should fail)...
✓ Verification correctly failed: ...

Step 10: Testing verification with tampered Q (should fail)...
✓ Verification correctly failed: ...

Step 11: Decrypting ciphertext...
✓ Decryption successful
  Original:  123456789012345678901234567890
  Decrypted: 123456789012345678901234567890
✓ Values match!

Step 12: Testing decryption with wrong label (should fail)...
✓ Decryption correctly failed: ...

Step 13: Testing decryption with tampered ciphertext (should fail)...
✓ Decryption correctly failed with wrong ciphertext

Step 14: Cleanup...
✓ Sensitive data zeroized

=== PVE Example Complete ===
```

## Security Considerations

### RSA Key Size

This example uses 3072-bit RSA keys for long-term security:
- **2048 bits**: Minimum for current use (acceptable until ~2030)
- **3072 bits**: Recommended for long-term security (secure beyond 2030)
- **4096 bits**: High security applications

### Memory Security

The example demonstrates proper cleanup:
- Private keys are zeroized after use
- Scalars implement `Free()` which zeroizes their internal memory; prefer calling `x.Free()` instead of manually touching `x.Bytes`.
- For raw byte slices (e.g., serialized keys), use `cbmpc.ZeroizeBytes()` to clear sensitive data

### Deterministic Encryption

PVE uses deterministic encryption (same plaintext + key + label = same ciphertext).
This is required for public verifiability but has implications:
- **Uniqueness**: Use a unique label per context (e.g., transaction ID, session ID).
- **Avoid repeats**: Do not encrypt the same value repeatedly with the same key/label.

## Integration with Custom KEMs

You can integrate PVE with any KEM implementation, including:
- Hardware Security Modules (HSMs)
- ML-KEM (post-quantum)
- Custom KEM schemes

See `pkg/cbmpc/internal/testkem/hsm_kem.go` for an HSM integration example.

## Related Tests

See comprehensive tests in:
- `pkg/cbmpc/pve/pve_test.go` - Basic PVE operations
- `pkg/cbmpc/pve/pve_concurrent_test.go` - Concurrent usage
- `pkg/cbmpc/pve/pve_isolation_test.go` - KEM isolation
- `pkg/cbmpc/pve/pve_hsm_test.go` - HSM integration
