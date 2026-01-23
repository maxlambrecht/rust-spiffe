# spiffe-rustls-tokio

[![Crates.io](https://img.shields.io/crates/v/spiffe-rustls-tokio.svg)](https://crates.io/crates/spiffe-rustls-tokio)
[![Docs.rs](https://docs.rs/spiffe-rustls-tokio/badge.svg)](https://docs.rs/spiffe-rustls-tokio/)
[![Safety](https://img.shields.io/badge/unsafe-forbidden-success.svg)](https://github.com/rust-secure-code/safety-dance)
[![Rust 1.87+](https://img.shields.io/badge/rust-1.87+-orange.svg)](https://www.rust-lang.org)

Tokio-native async accept/connect helpers for [`spiffe-rustls`](https://crates.io/crates/spiffe-rustls) configs.

Integrates `tokio-rustls` with automatic peer SPIFFE ID extraction. Provides `TlsAcceptor` and
`TlsConnector` that return `(TlsStream, PeerIdentity)` after successful handshakes. Runtime-agnostic
TLS configuration remains in `spiffe-rustls`.

---

## Installation

Add `spiffe-rustls-tokio` to your `Cargo.toml`:

```toml
[dependencies]
spiffe-rustls-tokio = "0.1"
spiffe-rustls = "0.4"
spiffe = { version = "0.11", features = ["x509-source"] }
```

---

## Quick Start

### 1. Create a `spiffe-rustls` configuration

```rust
use spiffe::X509Source;
use spiffe_rustls::{authorizer, mtls_client};

let source = X509Source::new().await?;
let client_config = mtls_client(source)
    .authorize(authorizer::any())
    .build()?;
```

### 2. Use `TlsConnector` or `TlsAcceptor`

```rust
use spiffe_rustls_tokio::TlsConnector;
use std::sync::Arc;

let connector = TlsConnector::new(Arc::new(client_config));
// ... use connector.connect() or connector.connect_addr()
```

---

## Example: Using `connect_addr` Convenience Method

```rust
use spiffe::X509Source;
use spiffe_rustls::{authorizer, mtls_client};
use spiffe_rustls_tokio::TlsConnector;
use std::net::SocketAddr;
use std::sync::Arc;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let source = X509Source::new().await?;
    let client_config = mtls_client(source)
        .authorize(authorizer::any())
        .build()?;

    let connector = TlsConnector::new(Arc::new(client_config));
    let addr: SocketAddr = "127.0.0.1:8443".parse()?;
    let server_name = rustls::pki_types::ServerName::try_from("example.org")?;

    // connect_addr combines TCP connection and TLS handshake
    match connector.connect_addr(addr, server_name).await {
        Ok((tls_stream, peer_identity)) => {
            if let Some(spiffe_id) = peer_identity.spiffe_id() {
                println!("Connected (SPIFFE ID: {})", spiffe_id);
            }
            // Use tls_stream...
        }
        Err(e) => eprintln!("Connection failed: {}", e),
    }

    Ok(())
}
```

---

## API Overview

### Main Types

- **`TlsAcceptor`** — Server-side TLS acceptor that extracts peer SPIFFE identity
- **`TlsConnector`** — Client-side TLS connector that extracts peer SPIFFE identity
- **`PeerIdentity`** — Contains the extracted SPIFFE ID from the peer certificate
- **`Error`** — Error type for TLS and identity extraction failures

### Key Methods

- **`TlsAcceptor::accept()`** — Accepts a TLS connection and returns `(TlsStream, PeerIdentity)`
- **`TlsConnector::connect()`** — Establishes a TLS connection and returns `(TlsStream, PeerIdentity)`
- **`TlsConnector::connect_addr()`** — Convenience method that combines TCP connection and TLS handshake
- **`PeerIdentity::spiffe_id()`** — Returns the peer's SPIFFE ID, if present

---

## Examples

The crate includes complete working examples that demonstrate real mTLS connections using SPIRE.

### Prerequisites

- A running SPIRE agent with Workload API accessible
- The `SPIFFE_ENDPOINT_SOCKET` environment variable set (or use default Unix socket path)
- Both client and server workloads registered with SPIRE

### Running the Examples

The examples are located in the `examples/` directory:

- **`mtls_tcp_server`** - A server that accepts mTLS connections and extracts peer SPIFFE IDs
- **`mtls_tcp_client`** - A client that connects to the server and extracts peer SPIFFE IDs

To run the examples:

```bash
# Terminal 1: Start the server
cargo run --package spiffe-rustls-tokio --example mtls_tcp_server

# Terminal 2: Run the client
cargo run --package spiffe-rustls-tokio --example mtls_tcp_client
```

The examples will:

- Connect to SPIRE via the Workload API to obtain X.509 SVIDs and trust bundles
- Perform mutual TLS handshakes with automatic certificate rotation support
- Extract and display peer SPIFFE IDs from certificates
- Exchange messages over the encrypted connection

The server listens on `127.0.0.1:8443` by default. Both examples demonstrate:

- Authorization policies (trust domains, exact SPIFFE IDs)
- Trust domain policies (LocalOnly, AllowList)
- Peer identity extraction using `PeerIdentity::spiffe_id()`
- Error handling for TLS and identity extraction failures

## Peer Identity Extraction

After a successful TLS handshake, the peer's SPIFFE ID is extracted from their certificate's URI SAN.

According to the SPIFFE specification, an X.509-SVID must contain **exactly one** SPIFFE ID. When using `spiffe-rustls` verifiers correctly, this is enforced during the TLS handshake.

**API behavior:**
- **Exactly one SPIFFE ID**: Extracted and stored in `PeerIdentity::spiffe_id`
- **Missing/multiple SPIFFE IDs or no peer certificates**: `spiffe_id` is `None` (no error; `accept()`/`connect()` succeed)
- **Certificate parse failure**: Returns `Error::CertParse` (`accept()`/`connect()` fail)

A `None` value for `spiffe_id` is unexpected in SPIFFE-compliant configurations and may indicate misconfiguration or a non-SPIFFE peer.

## License

Licensed under the Apache License, Version 2.0.
