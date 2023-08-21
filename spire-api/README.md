# Rust SPIRE API Library

This library provides support for SPIRE specific APIs in Rust.

## Features

- **Delegated Identity API support**: Facilitates authorized workloads to obtain SVIDs (SPIFFE Verifiable Identity
  Documents) and bundles on behalf of others that cannot be directly attested by SPIRE Agent. This feature enhances
  identity support for complex scenarios, including those where workloads cannot be directly recognized by SPIRE.

## Installation

Include this line in your `Cargo.toml`:

```toml
[dependencies]
spire-api = "0.1.0"
```

## Usage

A basic example:

```rust
use spire_api::delegated_identity;
// Your code here...
```

## Delegated Identity API

For more information about the SPIRE Delegated Identity API, refer to
the [official documentation](https://spiffe.io/docs/latest/spire/using/getting-started/).

## License

This library is licensed under the Apache License. See the [LICENSE.md](../LICENSE) file for details.
