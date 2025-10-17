# Threshold ECDSA MPC with PVE Backup Example

This example demonstrates a production-grade implementation of multi-party ECDSA with secure key backup using Publicly Verifiable Encryption (PVE). It showcases the complete workflow from key generation to signing, with secure backup, recovery, and key refresh capabilities.

## Overview

This example implements:

1. **Secure Communication**: mTLS-based transport between 4 parties with certificate-based authentication
2. **Distributed Key Generation**: 4-of-4 ECDSA key generation on P-256 curve
3. **Access Control Structures**: Flexible threshold policies for secret sharing
4. **Signing**: Collaborative signing with all 4 parties online
5. **Secure Backup**: PVE-based encryption of key shares with public verifiability
6. **Key Recovery**: Demonstration of secure key restoration from encrypted backup
7. **Key Refresh**: Proactive security through periodic key share updates

Unlike other examples that use mocknet, this example uses production-grade mTLS networking suitable for real-world deployments.

## Features

### Security Features
- ✓ Mutual TLS (mTLS) authentication between parties
- ✓ Certificate-based identity verification
- ✓ Secure distributed key generation (no single point of trust)
- ✓ Publicly verifiable encryption for backups
- ✓ Memory zeroization of sensitive data
- ✓ Production-ready network transport

### Protocol Features
- ✓ 4-of-4 ECDSA DKG on P-256
- ✓ Access control structures (threshold, AND, OR gates)
- ✓ Signing with all 4 parties online
- ✓ PVE encryption/decryption
- ✓ Ciphertext verification
- ✓ Key recovery demonstration
- ✓ Threshold key refresh (proactive security)

## Prerequisites

- Go 1.19 or later
- CGO enabled (for cb-mpc bindings)
- OpenSSL (for TLS)

## Quick Start

### 1. Generate TLS Certificates

```bash
cd examples/ecdsa-mpc-with-backup
make certs
```

This generates:
- Root CA certificate
- Per-party certificates and private keys
- All certificates support both server and client authentication (mTLS)

### 2. Run the Example

Open four terminal windows and run one party in each:

**Terminal 1 (Alice):**
```bash
make run-alice
```

**Terminal 2 (Bob):**
```bash
make run-bob
```

**Terminal 3 (Charlie):**
```bash
make run-charlie
```

**Terminal 4 (Dave):**
```bash
make run-dave
```

All four parties will:
1. Establish mTLS connections
2. Perform ECDSA DKG (4-of-4)
3. Sign a test message (all parties online)
4. Backup their key shares with PVE
5. Verify and recover from backup
6. Refresh key shares for proactive security

## Example Output

```
[alice] mTLS transport established with 3 parties
[alice] Starting Threshold ECDSA MPC with PVE Backup Demo
[alice] ======================================================
[alice] Step 1: Creating 2-of-3 threshold access structure...
[alice] ✓ Access structure created: Threshold(2, Leaf(alice), Leaf(bob), Leaf(charlie))
[alice]   This means any 2 of the 3 parties can sign
[alice] Step 2: Performing threshold ECDSA DKG (P-256, 2-of-3)...
[alice] ✓ Threshold DKG completed successfully
[alice]   Public Key: 04abc123...
[alice] Step 3: Threshold signing with quorum (alice + bob)...
[alice]   Message: "Hello, MPC World!"
[alice]   Message Hash (SHA-256): e3b0c442...
[alice] ✓ Signature created (I am the receiver)
[alice]   Signature: 3045022100...
[alice] Step 4: Creating PVE backup of key share...
[alice]   Backup Encryption Key generated
[alice] ✓ Key backed up with PVE
[alice]   Backup Label: backup-alice-1234567890
[alice]   Ciphertext size: 384 bytes
[alice] Step 5: Verifying PVE backup...
[alice] ✓ PVE backup verified successfully
[alice] Step 6: Demonstrating key recovery from backup...
[alice] ✓ Key recovered successfully and verified to match original
[alice] Step 7: Refreshing threshold key shares...
[alice] ✓ Key refresh completed - shares are now updated
[alice]   Verified: Refreshed key has same public key
[alice] ======================================================
[alice] Demo completed successfully!
```

## Configuration

### Cluster Configuration (`cluster.json`)

```json
{
  "ca_cert": "examples/ecdsa-mpc-with-backup/certs/rootCA.pem",
  "parties": [
    {
      "name": "alice",
      "address": "127.0.0.1:8001",
      "cert": "examples/ecdsa-mpc-with-backup/certs/alice-cert.pem",
      "key": "examples/ecdsa-mpc-with-backup/certs/alice-key.pem"
    },
    {
      "name": "bob",
      "address": "127.0.0.1:8002",
      "cert": "examples/ecdsa-mpc-with-backup/certs/bob-cert.pem",
      "key": "examples/ecdsa-mpc-with-backup/certs/bob-key.pem"
    },
    {
      "name": "charlie",
      "address": "127.0.0.1:8003",
      "cert": "examples/ecdsa-mpc-with-backup/certs/charlie-cert.pem",
      "key": "examples/ecdsa-mpc-with-backup/certs/charlie-key.pem"
    },
    {
      "name": "dave",
      "address": "127.0.0.1:8004",
      "cert": "examples/ecdsa-mpc-with-backup/certs/dave-cert.pem",
      "key": "examples/ecdsa-mpc-with-backup/certs/dave-key.pem"
    }
  ]
}
```

### Command-Line Options

- `--config`: Path to cluster configuration file (default: `examples/ecdsa-mpc-with-backup/cluster.json`)
- `--self`: Name of this party (required: `alice`, `bob`, `charlie`, or `dave`)
- `--message`: Message to sign (default: `"Hello, MPC World!"`)
- `--timeout`: Protocol timeout (default: `90s`)

### Environment Variables

- `SAVE_BACKUP=1`: Save the encrypted backup to a hex-encoded file

Example:
```bash
SAVE_BACKUP=1 make run-alice
```

## Advanced Usage

### Custom Message Signing

```bash
# Terminal 1
go run . --self=alice --message="Sign this message"

# Terminal 2
go run . --self=bob --message="Sign this message"
```

### Save Encrypted Backups

```bash
# Terminal 1
SAVE_BACKUP=1 make run-alice

# Terminal 2
SAVE_BACKUP=1 make run-bob
```

This creates `backup-alice.hex` and `backup-bob.hex` files containing the PVE-encrypted key shares.

## Architecture

### Network Layer

The example uses the `tlsnet` package for mTLS-based communication:

```go
transport, err := tlsnet.New(tlsnet.Config{
    Self:        selfIndex,
    Names:       names,
    Addresses:   addresses,
    Certificate: cert,
    RootCAs:     caPool,
})
```

Features:
- Long-lived TLS 1.3 connections
- Mutual certificate verification
- Automatic connection management
- Binary framing protocol
- Concurrent send/receive

### Protocol Flow

```
1. mTLS Handshake
   ├─ Alice, Bob, Charlie, Dave establish connections
   ├─ Certificate verification for all parties
   └─ Secure channels established

2. Distributed Key Generation (4-of-4)
   ├─ All 4 parties participate in DKG
   ├─ No single point of trust
   ├─ Each party gets a share
   └─ Shared public key computed

3. Signing (4-of-4)
   ├─ All 4 parties cooperate to sign
   ├─ Message hashing (SHA-256)
   ├─ Multi-round signing protocol
   └─ Valid ECDSA signature produced

4. PVE Backup (Per-Party)
   ├─ Each party generates KEM key pair
   ├─ Key share → Scalar conversion
   ├─ PVE encryption with unique label
   └─ Ciphertext stored

5. Verification (Per-Party)
   ├─ Extract Q point from ciphertext
   ├─ Verify ciphertext validity
   └─ Public verifiability confirmed

6. Recovery (Per-Party)
   ├─ PVE decryption with private DK
   ├─ Scalar → Key reconstruction
   └─ Verification against original

7. Key Refresh
   ├─ All parties participate
   ├─ Shares updated without changing public key
   └─ Proactive security achieved
```

### Security Considerations

**Memory Safety:**
- Key bytes are zeroized after use with `cbmpc.ZeroizeBytes()`
- Scalars are zeroized with `scalar.Zeroize()`
- Deferred cleanup ensures memory clearing on all paths

**Network Security:**
- TLS 1.3 minimum version enforced
- Mutual authentication required (mTLS)
- Certificate identity binding to party names
- Per-party key pairs (no shared keys)

**Key Management:**
- Keys never leave party's memory in plaintext
- PVE provides publicly verifiable encryption
- Backups are encrypted with KEM
- Recovery requires private decryption key

**Production Readiness:**
- Proper error handling throughout
- Timeouts on all operations
- Resource cleanup with `defer`
- Finalizers on C++ resources

## Protocol Details

### Distributed ECDSA DKG (4-of-4)

The distributed key generation protocol ensures:
- Each of the 4 parties holds a share of the private key
- No single party can learn the complete private key
- All 4 parties are required online for signing (in this example)
- The public key is jointly computed and known to all
- Security holds even if one party is malicious (up to abort)
- Threshold flexibility: Different thresholds (k-of-n) can be configured via access structures

### PVE (Publicly Verifiable Encryption)

PVE provides:
- **Encryption**: Encrypt scalar values under a public key
- **Public Verifiability**: Anyone can verify ciphertext correctness without the private key
- **Decryption**: Only the holder of the private key can decrypt
- **Security**: CCA2-secure under standard assumptions

Use cases:
- Secure key backup to cloud storage
- Key escrow with third-party verification
- Regulatory compliance (auditable backups)
- Disaster recovery

## Comparison with Other Examples

| Feature | ecdsa-mpc-with-backup | agree-random-mp | pve |
|---------|----------------------|-----------------|-----|
| Network | mTLS (production) | mTLS | None (single-party) |
| Protocol | ECDSA DKG + Sign | AgreeRandom | PVE only |
| Threshold | 4-of-4 | N/A | 1 |
| Parties | 4 | 3+ | 1 |
| Key Refresh | Yes | No | No |

## Common Issues

### Connection Timeout

**Problem**: Parties fail to connect within 10 seconds

**Solutions**:
- Ensure both parties are started close together in time
- Check firewall rules allow connections on specified ports
- Verify addresses in `cluster.json` are correct

### Certificate Errors

**Problem**: TLS handshake failures

**Solutions**:
- Run `make clean && make certs` to regenerate certificates
- Ensure certificate paths in `cluster.json` are correct
- Check that certificates have not expired

### Protocol Failures

**Problem**: MPC protocol fails mid-execution

**Solutions**:
- Ensure both parties use the same message (for signing)
- Check that network is stable during protocol execution
- Increase timeout with `--timeout=120s` for slow networks

## Cleanup

Remove all generated files:

```bash
make clean
```

This removes:
- TLS certificates
- Private keys
- Backup files

## Further Reading

- [cb-mpc C++ Documentation](../../cb-mpc/README.md)
- [Threshold ECDSA Multi-Party Protocol Details](../../pkg/cbmpc/ecdsamp/doc.go)
- [Access Structure Documentation](../../pkg/cbmpc/accessstructure/doc.go)
- [PVE Protocol Details](../../pkg/cbmpc/pve/doc.go)
- [TLS Transport Implementation](../tlsnet/transport.go)

## References

- Lindell, Y. (2017). "Fast Secure Two-Party ECDSA Signing." CRYPTO 2017.
- Publicly Verifiable Encryption based on Paillier and ElGamal encryption schemes
- TLS 1.3 RFC: https://www.rfc-editor.org/rfc/rfc8446

## License

See [LICENSE](../../LICENSE) in the root directory.
