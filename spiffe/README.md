# Rust SPIFFE Library

This utility library enables interaction with the [SPIFFE Workload API](https://github.com/spiffe/spiffe/blob/main/standards/SPIFFE_Workload_API.md). It allows fetching of X.509 and JWT SVIDs, bundles and supports watch/stream updates. The types in the library are in compliance with [SPIFFE standards](https://github.com/spiffe/spiffe/tree/main/standards). More about SPIFFE can be found at [spiffe.io](https://spiffe.io/).

[![crates.io](https://img.shields.io/crates/v/spiffe.svg)](https://crates.io/crates/spiffe)
[![Build](https://github.com/maxlambrecht/rust-spiffe/actions/workflows/ci.yml/badge.svg)](https://github.com/maxlambrecht/rust-spiffe/actions/workflows/ci.yml)
[![docs.rs](https://docs.rs/spiffe/badge.svg)](https://docs.rs/spiffe)
[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://github.com/maxlambrecht/rust-spiffe/blob/main/LICENSE)

## Getting Started

Include `spiffe` in your `Cargo.toml` dependencies to get both the SPIFFE types (`spiffe-types`) and the Workload API
client (`workload-api`) by default:

```toml
[dependencies]
spiffe = "0.6.6"
```

## Examples of Usage

### Creating a `WorkloadApiClient`

Create client using the endpoint socket path:

```rust
let mut client = WorkloadApiClient::new_from_path("unix:/tmp/spire-agent/public/api.sock").await?;
```

Or by using the `SPIFFE_ENDPOINT_SOCKET` environment variable:

```rust
let mut client = WorkloadApiClient::default().await?;
```

### Fetching X.509 Materials

Fetch the default X.509 SVID, a set of X.509 bundles, all X.509 materials, or watch for updates on the X.509 context and bundles.

```rust
// fetch the default X.509 SVID
let x509_svid: X509Svid = client.fetch_x509_svid().await?;

// fetch a set of X.509 bundles (X.509 public key authorities)
let x509_bundles: X509BundleSet = client.fetch_x509_bundles().await?;

// fetch all the X.509 materials (SVIDs and bundles)
let x509_context: X509Context = client.fetch_x509_context().await?;

// get the X.509 chain of certificates from the SVID
let cert_chain: &Vec<Certificate> = x509_svid.cert_chain();

// get the private key from the SVID
let private_key: &PrivateKey = x509_svid.private_key();

// parse a SPIFFE trust domain
let trust_domain = TrustDomain::try_from("example.org")?;

// get the X.509 bundle associated to the trust domain
let x509_bundle: &X509Bundle = x509_bundles.get_bundle(&trust_domain)?;

// get the X.509 authorities (public keys) in the bundle
let x509_authorities: &Vec<Certificate> = x509_bundle.authorities();

// watch for updates on the X.509 context
let mut x509_context_stream = client.stream_x509_contexts().await?;
while let Some(x509_context_update) = x509_context_stream.next().await {
    match x509_context_update {
        Ok(update) => {
            // handle the updated X509Context
        }
        Err(e) => {
            // handle the error
        }
    }
}

// watch for updates on the X.509 bundles 
let mut x509_bundle_stream = client.stream_x509_bundles().await?;
while let Some(x509_bundle_update) = x509_bundle_stream.next().await {
    match x509_bundle_update {
        Ok(update) => {
            // handle the updated X509 bundle
        }
        Err(e) => {
            // handle the error
        }
    }
}
```

### Fetching X.509 Materials using `X509Source`

A convenient way to fetch X.509 materials is by using the `X509Source`:

```rust
use spiffe::X509Source;
use spiffe::BundleSource;
use spiffe::TrustDomain;
use spiffe::X509Svid;
use spiffe::SvidSource;

async fn fetch_x509_materials() -> Result<(), Box<dyn std::error::Error>> {
    // Create a new X509Source
    let x509_source = X509Source::default().await?;

    // Fetch the SVID
    let svid = x509_source.get_svid()?.ok_or("No X509Svid found")?;

    // Fetch the bundle for a specific trust domain
    let trust_domain = spiffe::TrustDomain::new("example.org"); // Replace with the appropriate trust domain
    let bundle = x509_source.get_bundle_for_trust_domain(&trust_domain)?.ok_or("No bundle found for trust domain")?;

    Ok(())
}
```

### Fetching and Validating JWT Tokens and Bundles

Fetch JWT tokens, parse and validate them, fetch JWT bundles, or watch for updates on the JWT bundles.

```rust
// parse a SPIFFE ID to ask a token for
let spiffe_id = SpiffeId::try_from("spiffe://example.org/my-service")?;

// fetch a jwt token for the provided SPIFFE-ID and with the target audience `service1.com`
let jwt_token = client.fetch_jwt_token(&["audience1", "audience2"], Some(&spiffe_id)).await?;

// fetch the jwt token and parses it as a `JwtSvid`
let jwt_svid = client.fetch_jwt_svid(&["audience1", "audience2"], Some(&spiffe_id)).await?;

// fetch a set of jwt bundles (public keys for validating jwt token)
let jwt_bundles = client.fetch_jwt_bundles().await?;

// parse a SPIFFE trust domain
let trust_domain = TrustDomain::try_from("example.org")?;

// get the JWT bundle associated to the trust domain
let jwt_bundle: &JwtBundle = jwt_bundles.get_bundle(&trust_domain)?;

// get the JWT authorities (public keys) in the bundle
let jwt_authority: &JwtAuthority = jwt_bundle.find_jwt_authority("a_key_id")?;

// parse a `JwtSvid` validating the token signature with a JWT bundle source.
let validated_jwt_svid = JwtSvid::parse_and_validate(&jwt_token, &jwt_bundles_set, &["service1.com"])?;

// watch for updates on the JWT bundles 
let mut jwt_bundle_stream = client.stream_jwt_bundles().await?;
while let Some(jwt_bundle_update) = jwt_bundle_stream.next().await {
    match jwt_bundle_update {
        Ok(update) => {
            // handle the updated JWT bundle
        }
        Err(e) => {
            // handle the error
        }
    }
}
```

For more detailed examples and additional features, refer to the [documentation](https://docs.rs/spiffe).

## License

This library is licensed under the Apache License. See the [LICENSE.md](../LICENSE) file for details.
