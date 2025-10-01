# ECDSA 2PC with mTLS Demo

This demo demonstrates production-ready two-party ECDSA (Elliptic Curve Digital Signature Algorithm) using mutual TLS (mTLS) for secure communication between parties.

**Note**: The `MTLSSession` implementation is located in `examples/mtls_session.go` as a reference implementation. Production users should implement their own session types based on their specific networking requirements (gRPC, HTTP/2, custom protocols, etc.).

## Overview

The demo shows:
- **Secure Key Generation**: Distributed key generation between two parties
- **Message Signing**: Collaborative signature creation using 2PC ECDSA protocol
- **Signature Verification**: Standard ECDSA signature verification
- **Key Refresh**: Proactive security through key share refresh
- **Production Security**: Mutual TLS authentication and encryption

## Security Features

### Mutual TLS (mTLS)
- **Client Authentication**: Both parties authenticate each other using X.509 certificates
- **Transport Encryption**: All communication encrypted with TLS 1.2+
- **Certificate Validation**: Full certificate chain validation with custom CA
- **Perfect Forward Secrecy**: Ephemeral key exchange for each session

### ECDSA 2PC Protocol
- **Threshold Cryptography**: No single party holds the complete private key
- **Secure Multi-Party Computation**: Cryptographically secure protocol execution
- **Constant-Time Operations**: Side-channel attack resistance
- **Proactive Security**: Key refresh capability for long-term security

## Quick Start

### 1. Generate Certificates
```bash
./generate_certs.sh
```

This creates:
- `certs/ca-cert.pem` - Certificate Authority (CA) certificate
- `certs/server-cert.pem`, `certs/server-key.pem` - Server certificates for Party 0
- `certs/client1-cert.pem`, `certs/client1-key.pem` - Client certificates for Party 1

### 2. Run the Demo
```bash
./run_demo.sh
```

This automatically:
- Builds the demo application
- Starts both parties (Party 0 as server, Party 1 as client)
- Demonstrates the complete ECDSA 2PC workflow
- Shows logs from both parties

### 3. Manual Execution

For manual control, run each party in separate terminals:

**Terminal 1 (Party 0 - Server):**
```bash
./ecdsa2pc_mtls -party=0 -server="localhost:8443" -client="localhost:8444"
```

**Terminal 2 (Party 1 - Client):**
```bash
./ecdsa2pc_mtls -party=1 -server="localhost:8443" -client="localhost:8444"
```

## Command Line Options

- `-party`: Party index (0 or 1)
- `-server`: Server address for Party 0 (default: localhost:8443)
- `-client`: Client address for Party 1 (default: localhost:8444)
- `-certs`: Certificate directory (default: ./certs)
- `-message`: Message to sign (default: "Hello, MPC ECDSA with mTLS!")

## Protocol Flow

1. **mTLS Handshake**: Parties establish secure, authenticated connection
2. **Key Generation**: Distributed generation of ECDSA key shares
3. **Message Signing**: Collaborative signature creation
4. **Signature Verification**: Validate signature using standard ECDSA
5. **Key Refresh**: Generate new key shares while preserving public key

## Network Architecture

```
Party 0 (Server)          Party 1 (Client)
├── Role: Server          ├── Role: Client
├── Cert: server-cert     ├── Cert: client1-cert
├── Listen: 8443          ├── Connect to: 8443
└── ECDSA Role: 0/1       └── ECDSA Role: 1/0
```

Party 0 acts as the TLS server and listens for connections. Party 1 acts as the TLS client and connects to Party 0. The ECDSA protocol roles are assigned dynamically during key generation.

## Security Considerations

### Production Deployment

1. **Certificate Management**:
   - Use proper PKI infrastructure (not self-signed certificates)
   - Implement certificate rotation and revocation
   - Store private keys in hardware security modules (HSMs)

2. **Network Security**:
   - Deploy behind firewalls with restricted access
   - Use VPNs or private networks for inter-party communication
   - Monitor and log all network traffic

3. **Operational Security**:
   - Implement proper key backup and recovery procedures
   - Use hardware-backed key storage when possible
   - Regular security audits and penetration testing

### Threat Model

This implementation protects against:
- **Network Eavesdropping**: TLS encryption prevents traffic analysis
- **Man-in-the-Middle**: Mutual authentication prevents impersonation
- **Single Point of Failure**: No single party controls the private key
- **Replay Attacks**: TLS provides built-in replay protection

## Dependencies

- **Go 1.21+**: Modern Go runtime with CGO support
- **OpenSSL 3.2+**: Cryptographic library (custom build required)
- **cb-mpc**: Coinbase MPC C++ library
- **Network**: TCP connectivity between parties

## Troubleshooting

### Common Issues

1. **Certificate Errors**:
   ```
   Error: tls: bad certificate
   ```
   - Regenerate certificates with `./generate_certs.sh`
   - Check certificate paths and permissions

2. **Connection Refused**:
   ```
   Error: dial tcp: connection refused
   ```
   - Ensure Party 0 starts first (server role)
   - Check firewall and network connectivity
   - Verify port availability

3. **Protocol Timeout**:
   ```
   Error: context deadline exceeded
   ```
   - Ensure both parties start within the timeout window
   - Check network latency and bandwidth

### Debug Mode

For detailed debugging, run with verbose logging:
```bash
GODEBUG=x509util=1,tls=1 ./ecdsa2pc_mtls -party=0
```

## Performance

Typical performance on modern hardware:
- **Key Generation**: ~100-500ms per party
- **Signature Creation**: ~50-200ms per signature
- **Key Refresh**: ~100-500ms per party
- **Network Overhead**: ~1-5ms (local network)

Performance varies based on:
- CPU performance (especially for elliptic curve operations)
- Network latency between parties
- Certificate chain complexity
- System load and resource availability

## References

- [Coinbase MPC Documentation](https://github.com/coinbase/cb-mpc)
- [RFC 8446: TLS 1.3](https://tools.ietf.org/html/rfc8446)
- [RFC 5246: TLS 1.2](https://tools.ietf.org/html/rfc5246)
- [FIPS 186-4: ECDSA Standard](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.186-4.pdf)