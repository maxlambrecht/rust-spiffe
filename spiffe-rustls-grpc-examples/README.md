# spiffe-rustls gRPC Examples

This crate contains **gRPC (tonic + tonic-rustls)** examples for
[`spiffe-rustls`](../spiffe-rustls).

It is **not published** and exists only as a reference and testing aid.
The core library intentionally avoids gRPC and protobuf build dependencies.

---

## Prerequisites

The examples require:

- A running **SPIRE agent**
- A valid SPIFFE Workload API socket (`SPIFFE_ENDPOINT_SOCKET`)
- Local DNS resolution for `example.org`

For local testing, add:

```text
127.0.0.1 example.org
````

to `/etc/hosts`.

---

## Running the examples

From the repository root:

### Server

```bash
cargo run -p spiffe-rustls-grpc-examples --bin grpc_server_mtls
```

### Client

```bash
cargo run -p spiffe-rustls-grpc-examples --bin grpc_client_mtls
```

Enable debug logging if needed:

```bash
RUST_LOG=debug cargo run -p spiffe-rustls-grpc-examples --bin grpc_server_mtls
```

---

## Notes

* These examples use the SPIFFE Workload API; they do not start or configure SPIRE.
* TLS name (SNI) verification still applies; the DNS name must match the certificate SAN.
