# spiffe-rustls

`spiffe-rustls` integrates [`rustls`](https://crates.io/crates/rustls) with SPIFFE/SPIRE using the
[`spiffe`](https://crates.io/crates/spiffe) crate’s `X509Source` (SPIRE Workload API).

It provides builders for `rustls::ClientConfig` and `rustls::ServerConfig` backed by a **live**
`X509Source`. When the SPIRE agent rotates SVIDs or trust bundles, **new TLS handshakes automatically
use the updated material**, without restarting the application.

This crate focuses on **TLS authentication and connection-level authorization via SPIFFE IDs**, while
delegating cryptography and TLS mechanics to `rustls`.

---

## Features

`spiffe-rustls` supports multiple `rustls` crypto providers.

```toml
[features]
default = ["ring"]
ring = ["rustls/ring"]
aws-lc-rs = ["rustls/aws_lc_rs"]
````

* **Default:** `ring`
* **Optional:** `aws-lc-rs`

Exactly **one** provider must be enabled. Enabling both results in a compile-time error.

To enable `aws-lc-rs`:

```bash
cargo add spiffe-rustls --no-default-features --features aws-lc-rs
```

---

## Crypto providers

* **`ring`**
  Follows `rustls` defaults and is recommended for general use.

* **`aws-lc-rs`**
  Targets environments that require AWS-LC–based cryptography (for example, FIPS-aligned systems).

Provider selection affects only cryptographic primitives; **SPIFFE semantics and API behavior are
identical** across providers.
`spiffe-rustls` is crypto-provider agnostic and delegates all cryptographic primitives to the selected
`rustls` crypto provider.

---

## Public API

The public API is intentionally small:

* `ClientConfigBuilder`, `ClientConfigOptions`
* `ServerConfigBuilder`, `ServerConfigOptions`

---

## Builders

### ClientConfigBuilder

Constructs a `rustls::ClientConfig` that:

* presents the current SPIFFE X.509 SVID as the client certificate
* validates the server certificate chain against the trust domain bundle
* authorizes the server by SPIFFE ID (URI SAN)

### ServerConfigBuilder

Constructs a `rustls::ServerConfig` that:

* presents the current SPIFFE X.509 SVID as the server certificate
* requires and validates client certificates (mTLS)
* authorizes the client by SPIFFE ID (URI SAN)

Both builders retain an `Arc<X509Source>` and always use the **latest SVIDs and bundles** for new TLS
handshakes.

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

The resulting `ClientConfig` can be used directly with `rustls`, or integrated into higher-level
libraries such as `tokio-rustls` or `tonic-rustls`.

---

## Examples

### Prerequisites

All examples require:

* A **running SPIRE agent**
* A valid SPIFFE Workload API socket (`SPIFFE_ENDPOINT_SOCKET`)
* Local DNS resolution for `example.org`

For local testing, add the following entry to `/etc/hosts`:

```text
127.0.0.1 example.org
```

---

### Raw TLS (tokio-rustls)

Direct integration with `rustls` using `tokio-rustls`.

* `mtls_tcp_server.rs`
* `mtls_tcp_client.rs`

Run with:

```bash
cargo run --features tcp-examples --example mtls_tcp_server
cargo run --features tcp-examples --example mtls_tcp_client
```

(Optional debug logging)

```bash
RUST_LOG=debug cargo run --features tcp-examples --example mtls_tcp_server
```

---

### gRPC (tonic + tonic-rustls)

gRPC integration using `tonic` and `tonic-rustls`.

* `grpc_server_mtls.rs`
* `grpc_client_mtls.rs`

Run with:

```bash
cargo run --features grpc-examples --example grpc_server_mtls
cargo run --features grpc-examples --example grpc_client_mtls
```

---

## Notes

* All examples rely on the SPIFFE Workload API and do not start or configure SPIRE.
* TLS name (SNI) verification still applies; the DNS name must match the certificate SAN.

---

## License

Licensed under the Apache License 2.0.
See [LICENSE.md](../LICENSE) for details.
