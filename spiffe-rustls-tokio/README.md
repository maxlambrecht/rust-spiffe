# spiffe-rustls-tokio

[![Crates.io](https://img.shields.io/crates/v/spiffe-rustls-tokio.svg)](https://crates.io/crates/spiffe-rustls-tokio)
[![Docs.rs](https://docs.rs/spiffe-rustls-tokio/badge.svg)](https://docs.rs/spiffe-rustls-tokio/)
[![Safety](https://img.shields.io/badge/unsafe-forbidden-success.svg)](https://github.com/rust-secure-code/safety-dance)
[![Rust 1.85+](https://img.shields.io/badge/rust-1.85+-orange.svg)](https://www.rust-lang.org)

Tokio-native accept/connect helpers for [`spiffe-rustls`](https://crates.io/crates/spiffe-rustls) configs.

This crate provides a small adapter layer that makes it easy to use SPIFFE mTLS with Tokio + rustls and to extract peer identity from TLS connections.

---

## Features

- **Runtime-agnostic core**: `spiffe-rustls` remains runtime-agnostic
- **Tokio integration**: Native async accept/connect operations
- **Peer identity extraction**: Automatically extract SPIFFE IDs from peer certificates

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

## ALPN for gRPC

When using this crate with gRPC, you'll want to configure ALPN protocols. The `spiffe-rustls` builders support this:

```rust
use spiffe_rustls::mtls_server;

let server_config = mtls_server(source)
    .authorize(authorizer::any())
    .with_alpn_protocols([b"h2"])  // HTTP/2 required for gRPC
    .build()?;
```

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

After a successful TLS handshake, the peer's SPIFFE ID is automatically extracted from their certificate's URI SAN. The `PeerIdentity` struct contains:

- `spiffe_id: Option<SpiffeId>` - The extracted SPIFFE ID, if present

### SPIFFE X.509-SVID Expectations

According to the SPIFFE specification, an X.509-SVID must contain **exactly one** SPIFFE ID in the URI SAN, and peers are expected to present certificates when mTLS is required. When using `spiffe-rustls` verifiers correctly, these requirements are enforced during the TLS handshake, and cases where `spiffe_id` is `None` should normally be unreachable.

### Observed API Behavior

This crate performs post-handshake identity extraction from connections that have already passed TLS verification. The behavior is:

- **Exactly one SPIFFE ID**: Extracted and stored in `spiffe_id`
- **Missing SPIFFE ID**: `spiffe_id` is set to `None` (no error; `accept()`/`connect()` succeed)
  - **SPIFFE perspective**: Invalid X.509-SVID; unexpected in SPIFFE-compliant configurations
- **Multiple SPIFFE IDs**: `spiffe_id` is set to `None` (no error; `accept()`/`connect()` succeed)
  - **SPIFFE perspective**: Invalid X.509-SVID; unexpected in SPIFFE-compliant configurations
- **No peer certificates**: `spiffe_id` is set to `None` (no error; `accept()`/`connect()` succeed)
  - **SPIFFE perspective**: Invalid for mTLS; unexpected in SPIFFE-compliant configurations
- **Certificate parse failure**: `accept()`/`connect()` return `Error::CertParse` and the connection is closed

**Note**: A `None` value for `spiffe_id` is unexpected in SPIFFE-compliant configurations and may indicate that the TLS configuration is not enforcing SPIFFE semantics, or that the peer is not presenting a valid SPIFFE X.509-SVID.

## License

Licensed under the Apache License, Version 2.0.
