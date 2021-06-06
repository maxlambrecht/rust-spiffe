# rust-spiffe
[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://github.com/maxlambrecht/rust-spiffe/blob/main/LICENSE)

## Overview

This library provides functions to interact with the [SPIFFE Workload API](https://github.com/spiffe/spiffe/blob/main/standards/SPIFFE_Workload_API.md) 
to fetch X.509 and JWT SVIDs and Bundles. It also provides types that comply with the [SPIFFE standards](https://github.com/spiffe/spiffe/tree/main/standards).

Under development.

## Examples

### Create a `WorkloadApiClient`

Providing the endpoint socket path as parameter:

```rust
let client = WorkloadApiClient::new("unix:/tmp/spire-agent/api/public.sock")?;
```

Providing the endpoint socket path through the environment variable `SPIFFE_ENDPOINT_SOCKET`:

```rust
let client = WorkloadApiClient::default()?;
```

### Fetching X.509 materials

```rust

// fetch the default X.509 SVID
let x509_svid: X509Svid = client.fetch_x509_svid()?;

// fetch a set of X.509 bundles (X.509 public key authorities)
let x509_bundles: X509BundleSet = client.fetch_x509_bundles()?;

// fetch all the X.509 materials (SVIDs and bundles)
let x509_context: X509Context = client.fetch_x509_context()?;

// get the X.509 chain of certificates from the SVID
let cert_chain: &Vec<Certificate> = x509_svid.cert_chain();

// get the private key from the SVID
let private_key: &PrivateKey = x509_svid.private_key();

// parse a SPIFFE trust domain
let trust_domain = TrustDomain::try_from("example.org")?;

// get the X.509 bundle associated to the trust domain
let x509_bundle: &X509Bundle = x509_bundles.get_bundle(&trust_domain).unwrap();

// get the X.509 authorities (public keys) in the bundle
let x509_authorities: &Vec<Certificate> = x509_bundle.authorities();
```


### Fetching JWT tokens and bundles and validating tokens

```rust

// parse a SPIFFE ID to ask a token for
let spiffe_id = SpiffeId::try_from("spiffe://example.org/my-service")?;

// fetch a jwt token for the provided SPIFFE-ID and with the target audience `service1.com`
let jwt_token = client.fetch_jwt_token(&["audience1", "audience2"], Some(&spiffe_id))?;

// fetch the jwt token and parses it as a `JwtSvid`
let jwt_svid = client.fetch_jwt_svid(&["audience1", "audience2"], Some(&spiffe_id))?;

// fetch a set of jwt bundles (public keys for validating jwt token)
let jwt_bundles = client.fetch_jwt_bundles()?;

// parse a SPIFFE trust domain
let trust_domain = TrustDomain::try_from("example.org")?;

// get the JWT bundle associated to the trust domain
let jwt_bundle: &JwtBundle = jwt_bundles.get_bundle(&trust_domain).unwrap();

// get the JWT authorities (public keys) in the bundle
let jwt_authority: &JwtAuthority = jwt_bundle.find_jwt_authority("a_key_id").unwrap();

// parse a JwtSvid validating the token signature with a JWT bundle source.
let validated_jwt_svid =
    match JwtSvid::parse_and_validate(&jwt_token, &jwt_bundles, &["audience1"]) {
        Ok(svid) => svid,
        Err(e) => return Err(e.into()),
    };
```
