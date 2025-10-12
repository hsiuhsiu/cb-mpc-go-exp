### tlsnet: mTLS Transport for Examples

This package provides a minimal, production-leaning `cbmpc.Transport` built on mutual TLS (mTLS) for the example programs.

- Identity model: Each party has a unique name (e.g., `p0`, `p1`), used as the TLS server name and embedded in the certificate subject/SAN. On connection, peers exchange their role IDs and the server verifies the claimed ID matches the certificate identity.
- Trust model: A demo root CA signs all party certificates. Clients verify servers via `ServerName` and CA. Servers require and verify client certificates, and we bind the presented certificate to the claimed peer ID.
- TLS version: TLS 1.3 minimum.

#### Generate certificates

From repository root:

```bash
scripts/run_example.sh run ./examples/tlsnet/cmd/gen-certs --output examples/agree-random-2p/certs --names p0,p1
```

For multi-party, include more names and adjust the output directory accordingly.

#### Configuration

Examples load a JSON cluster file with CA cert, party names, addresses, and per-party cert/key paths. Paths are sanitized to avoid directory traversal.

#### Security notes

- Certificates include `localhost` and `127.0.0.1` SANs for local demos. In production, generate certs with proper hostnames and lifetimes.
- The transport rejects connections whose certificate identity does not match the configured party name for the claimed role ID.
- Messages are length-prefixed and transmitted over persistent TLS connections.


