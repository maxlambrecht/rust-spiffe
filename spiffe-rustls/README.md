# spiffe-rustls

[![Crates.io](https://img.shields.io/crates/v/spiffe-rustls.svg)](https://crates.io/crates/spiffe-rustls)
[![Docs.rs](https://docs.rs/spiffe-rustls/badge.svg)](https://docs.rs/spiffe-rustls/)
![MSRV](https://img.shields.io/badge/MSRV-1.83-blue)

`spiffe-rustls` integrates [`rustls`](https://crates.io/crates/rustls) with SPIFFE/SPIRE using the
[`spiffe`](https://crates.io/crates/spiffe) crate’s `X509Source` (SPIFFE Workload API).

It provides builders for `rustls::ClientConfig` and `rustls::ServerConfig` backed by a **live**
`X509Source`. When the SPIRE agent rotates SVIDs or trust bundles, **new TLS handshakes automatically
use the updated material**, without restarting the application.

The crate focuses on **TLS authentication and connection-level authorization via SPIFFE IDs**, while
delegating all cryptography and TLS mechanics to `rustls`.

---

## Features

`spiffe-rustls` supports multiple `rustls` crypto providers:

```toml
[features]
default = ["ring"]
ring = ["rustls/ring"]
aws-lc-rs = ["rustls/aws_lc_rs"]
````

* **Default:** `ring`
* **Optional:** `aws-lc-rs`

Exactly **one** provider must be enabled. Enabling more than one results in a compile-time error.

Example (AWS-LC):

```bash
cargo add spiffe-rustls --no-default-features --features aws-lc-rs
```

Provider choice affects only cryptographic primitives; **SPIFFE semantics and API behavior are
identical** across providers.

---

## Public API

The public API is intentionally small:

* `ClientConfigBuilder`, `ClientConfigOptions`
* `ServerConfigBuilder`, `ServerConfigOptions`

Both builders retain an `Arc<X509Source>` and always use the **latest SVIDs and bundles** for new TLS
handshakes.

---

## Builders

### ClientConfigBuilder

Builds a `rustls::ClientConfig` that:

* presents the current SPIFFE X.509 SVID as the client certificate
* validates the server certificate chain against the trust domain bundle
* authorizes the server by SPIFFE ID (URI SAN)

### ServerConfigBuilder

Builds a `rustls::ServerConfig` that:

* presents the current SPIFFE X.509 SVID as the server certificate
* requires and validates client certificates (mTLS)
* authorizes the client by SPIFFE ID (URI SAN)

---

## Options

### ClientConfigOptions

```rust
pub struct ClientConfigOptions {
    pub trust_domain: TrustDomain,
    pub authorize_server: AuthorizeSpiffeId,
}
```

* `trust_domain`: trust domain whose bundle is used as the root of trust
* `authorize_server`: authorization hook invoked with the server SPIFFE ID

Use `ClientConfigOptions::allow_any(trust_domain)` to disable authorization while retaining full
authentication.

---

### ServerConfigOptions

```rust
pub struct ServerConfigOptions {
    pub trust_domain: TrustDomain,
    pub authorize_client: AuthorizeSpiffeId,
}
```

* `trust_domain`: trust domain whose bundle is used as the root of trust
* `authorize_client`: authorization hook invoked with the client SPIFFE ID

Use `ServerConfigOptions::allow_any(trust_domain)` to disable authorization while retaining full
authentication.

---

## Quick start

### 1. Create an X509Source

The source is configured via `SPIFFE_ENDPOINT_SOCKET`:

```rust
let source = spiffe::X509Source::new().await?;
```

---

### 2. Build a rustls client configuration

```rust
use spiffe_rustls::{ClientConfigBuilder, ClientConfigOptions};
use std::sync::Arc;

let opts = ClientConfigOptions {
    trust_domain: "example.org".try_into()?,
    authorize_server: Arc::new(|id: &str| {
        id == "spiffe://example.org/myservice"
    }),
};

let client_cfg = ClientConfigBuilder::new(source.clone(), opts)
    .build()
    .await?;
```

The resulting `ClientConfig` can be used directly with `rustls`, or integrated into
`tokio-rustls`, `tonic-rustls`, or similar libraries.

---

## Examples

### Prerequisites

All examples require:

* a running **SPIRE agent**
* a valid Workload API socket (`SPIFFE_ENDPOINT_SOCKET`)
* local DNS resolution for `example.org`

For local testing, add to `/etc/hosts`:

```text
127.0.0.1 example.org
```

---

### Raw TLS (tokio-rustls)

Direct TLS integration using `tokio-rustls`.

Examples:

* `mtls_tcp_server.rs`
* `mtls_tcp_client.rs`

```bash
cargo run --features tcp-examples --example mtls_tcp_server
cargo run --features tcp-examples --example mtls_tcp_client
```

---

### gRPC (tonic + tonic-rustls)

gRPC examples live in a **separate crate** (`spiffe-rustls-grpc-examples`) to avoid pulling gRPC and
protobuf build dependencies into the library.

```bash
cargo run -p spiffe-rustls-grpc-examples --bin grpc_server_mtls
cargo run -p spiffe-rustls-grpc-examples --bin grpc_client_mtls
```

---

## Notes

* Examples rely exclusively on the SPIFFE Workload API; they do not start or configure SPIRE.
* Standard TLS name (SNI) verification still applies; the DNS name must match the certificate SAN.

---

## License

Licensed under the Apache License, Version 2.0.
See [LICENSE](../LICENSE) for details.
