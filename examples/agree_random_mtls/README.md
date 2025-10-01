# Production mTLS Example: Agree Random Protocol

This example demonstrates production-ready usage of the cb-mpc-go library with mutual TLS (mTLS) authentication for secure multi-party computation.

## Overview

This example shows:
- ✅ **Real network communication** using TCP with mTLS
- ✅ **Certificate-based authentication** for all parties
- ✅ **Multi-terminal execution** simulating distributed parties
- ✅ **Production-ready patterns** easily adaptable to internet deployment
- ✅ **Configuration file** for easy setup and deployment

## Quick Start

### 1. Generate Certificates

Generate TLS certificates for all parties:

```bash
# From the examples/agree_random_mtls directory
./setup.sh
```

This will create a `certs/` directory with:
- CA certificate and key
- Individual certificates and keys for each party

### 2. Run the Protocol

Open **2 separate terminals** and run one party in each:

**Terminal 1 (Party 0):**
```bash
go run main.go -party 0
```

**Terminal 2 (Party 1):**
```bash
go run main.go -party 1
```

### 3. Verify Results

Both parties should output the **same random value**, proving they successfully executed the MPC protocol over authenticated channels.

Expected output:
```
=== Protocol completed successfully ===
Party 0 result: a1b2c3d4e5f6...
✅ All parties should have identical values above
```

## Configuration

Edit `config.json` to customize the setup:

```json
{
  "parties": [
    {
      "index": 0,
      "address": "localhost:8080",
      "cert_path": "certs/party-0/cert.pem",
      "key_path": "certs/party-0/key.pem"
    },
    {
      "index": 1,
      "address": "localhost:8081",
      "cert_path": "certs/party-1/cert.pem",
      "key_path": "certs/party-1/key.pem"
    }
  ],
  "ca_cert_path": "certs/ca.pem",
  "bit_length": 256,
  "timeout_seconds": 30
}
```

### Configuration Fields

- **parties**: List of all participating parties
  - `index`: Party index (0-based)
  - `address`: Network address in format `host:port`
  - `cert_path`: Path to party's certificate
  - `key_path`: Path to party's private key

- **ca_cert_path**: Path to CA certificate (for verifying peers)
- **bit_length**: Length of random value to generate (in bits)
- **timeout_seconds**: Timeout for protocol execution

## Multi-Party Setup (3+ parties)

To run with more than 2 parties:

1. Generate certificates for N parties:
```bash
../../scripts/certs/generate_certs.sh 3
```

2. Update `config.json` to include all parties

3. Open N terminals and run each party:
```bash
# Terminal 1
go run main.go -party 0

# Terminal 2
go run main.go -party 1

# Terminal 3
go run main.go -party 2
```

## Internet Deployment

To deploy across internet hosts:

### 1. Update Configuration

Change addresses from `localhost` to actual IP addresses or hostnames:

```json
{
  "parties": [
    {
      "index": 0,
      "address": "10.0.1.10:8080",
      ...
    },
    {
      "index": 1,
      "address": "10.0.1.11:8080",
      ...
    }
  ],
  ...
}
```

### 2. Distribute Certificates

- **Each party** needs:
  - Their own private key and certificate
  - The CA certificate
  - The configuration file
  - Certificates of all other parties (for verification)

- **Security**: Keep private keys (`key.pem`) secure!

### 3. Firewall Configuration

Ensure the specified ports are open for incoming TCP connections.

### 4. DNS/Hostname Support

The certificate generation script supports DNS names. Update `scripts/certs/generate_certs.sh` to add your hostnames to the certificate Subject Alternative Names (SAN).

## Security Features

This example implements production security best practices:

- ✅ **Mutual TLS (mTLS)**: Both client and server authenticate each other
- ✅ **Certificate validation**: Each party verifies peer certificates against expected values
- ✅ **TLS 1.3**: Uses the latest TLS version for best security
- ✅ **Perfect forward secrecy**: Each session uses ephemeral keys
- ✅ **Certificate pinning**: Party public keys are cryptographically bound to configuration

## Architecture

```
┌─────────────┐                      ┌─────────────┐
│   Party 0   │◄────mTLS (TCP)──────►│   Party 1   │
│ :8080       │                      │ :8081       │
│             │                      │             │
│ cert.pem    │                      │ cert.pem    │
│ key.pem     │                      │ key.pem     │
└─────────────┘                      └─────────────┘
       │                                    │
       └──────────► Verify with CA ◄────────┘
                   (ca.pem)
```

### Connection Pattern

To avoid connection conflicts, parties use a deterministic connection pattern:
- Party with **lower index** connects to parties with **higher index**
- Party with **higher index** listens for connections from parties with **lower index**

Example with 3 parties:
- Party 0: Connects to parties 1 and 2
- Party 1: Listens for party 0, connects to party 2
- Party 2: Listens for parties 0 and 1

This ensures exactly one TCP connection between each pair of parties.

## Troubleshooting

### "Connection refused" errors

- Make sure parties are started in order (lower index first helps)
- Verify firewall rules allow connections on specified ports
- Check that addresses in config.json are correct

### Certificate verification failures

- Ensure all certificates are generated with the same CA
- Verify certificate paths in config.json are correct
- Check that certificates are readable by the process

### Timeout errors

- Increase `timeout_seconds` in config.json
- Check network connectivity between hosts
- Verify all parties are running

### Port already in use

- Change port numbers in config.json
- Or kill processes using the ports: `lsof -ti tcp:<port> | xargs kill`

## Performance Notes

- First connection establishment takes ~100-500ms
- Protocol execution time depends on bit length and network latency
- Typical 256-bit AgreeRandom: 10-50ms over LAN, 50-200ms over internet

## Development vs Production

This example is production-ready but consider these enhancements for real deployments:

1. **Certificate Management**
   - Use a proper PKI/CA infrastructure
   - Implement certificate rotation
   - Use hardware security modules (HSM) for private keys

2. **Monitoring**
   - Add structured logging
   - Implement metrics collection
   - Set up alerting for failures

3. **High Availability**
   - Implement retry logic with exponential backoff
   - Add circuit breakers
   - Consider using a service mesh

4. **Configuration**
   - Use environment variables for sensitive data
   - Implement configuration validation
   - Support dynamic configuration updates

## References

- [cb-mpc C++ library](https://github.com/coinbase/cb-mpc)
- [MPC Security Considerations](../../pkg/mpc/SECURITY_TESTING.md)
- [TLS 1.3 Specification](https://tools.ietf.org/html/rfc8446)
