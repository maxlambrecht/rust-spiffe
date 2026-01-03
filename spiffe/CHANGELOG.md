# Changelog

## [0.10.0] – 2026-01-03

### Breaking

- Default feature set is now empty (default = []). Feature-gated capabilities (Workload API, X.509 parsing, JWT, etc.) must be explicitly enabled.
- `X509Source::new()` return type changed** from `Arc<X509Source>` to `X509Source` (cloneable).
- Module layout changes:** X.509 source moved to `spiffe::x509_source`; endpoint parsing moved under `spiffe::transport`.

### Added / Changed

- Clear **feature matrix** separating X.509, JWT, transport, and Workload API concerns.
- Heavy X.509 and JWT parsing dependencies are now **fully feature-gated** (`x509`, `jwt`).
- New Workload API tiers: `workload-api-core`, `workload-api-x509`, `workload-api-jwt`, `workload-api-full`
  (`workload-api` remains an alias for `-full`).
- Improved endpoint parsing: supports `tcp:IP:PORT`, IPv6, stricter unix path validation, and `FromStr`.
- Polished `X509Source` builder API and documentation.
- Integration tests are now feature-gated and `#[ignore]`.

**Migration:** see `docs/migration-spiffe-0.10.md`.


## [0.9.2] – 2025-12-30

### Changed
- Expose `Endpoint` and `EndpointError` in `transport` feature.

## [0.9.1] – 2025-12-30

### Changed
- Observability is now fully opt-in via features:
  - `logging` enables `log`
  - `tracing` enables `tracing`
  - precedence: `tracing` > `logging` > no-op
- `workload-api` no longer enables `log` implicitly (reduced default dependency surface).

### Documentation
- Documented observability feature precedence and clarified that features are additive/opt-in.

### Migration note
If you relied on `workload-api` enabling logging implicitly, enable `logging` explicitly:
`spiffe = { version = "0.9.1", features = ["workload-api", "logging"] }`


## [0.9.0] – 2025-12-30

### ⚠️ Breaking changes

- Offline JWT verification is now feature-gated.
    - `JwtSvid::parse_and_validate` requires enabling a `jwt-verify-*` feature.
- `SvidPicker::pick_svid` now returns `Option<usize>` instead of a reference.
- Internal feature renamed: `grpc` → `transport`.
- `GrpcClientError` replaced by `WorkloadApiError` and `TransportError`.
- MSRV bumped from 1.83 to 1.85.

### Added

- X509Source hardening:
    - Resource limits (SVIDs, bundles, bundle size)
    - Graceful shutdown with timeout
    - Metrics hooks and categorized error reporting
- Optional `tracing` feature for structured logging.
- New `X509SourceUpdates` API for update notifications.
- Stricter and more defensive JWT/JWKS parsing.

### Changed

- `JwtBundleSet` now uses deterministic ordering (`BTreeMap`).
- Default dependency and cryptography surface reduced via feature gating.

### Deprecated

- `JwtBundleSet::bundle_for` (use `get` instead).


## [0.8.0] – 2025-12-26

### Breaking Changes

* Removed the `spiffe-types` feature; core SPIFFE types are now always enabled.
* Refactored `WorkloadApiClient` to be non-mutable; all client methods now take `&self`.
* Removed legacy `Bundle`, `BundleRefSource`, `Svid`, and `SvidRefSource` traits.
* Introduced `BundleSource` and `SvidSource` returning shared `Arc` values.
* Standardized bundle lookup APIs (`get_bundle*` → `bundle_for*`).
* Replaced string-based socket handling with a typed `Endpoint` abstraction.
* Updated JWT-SVID parsing to use spec-correct `exp` handling.
* Refined `GrpcClientError` with explicit semantic variants and gRPC status mapping.

### Added

* First-class support for SVID hints for both X.509 and JWT identities.
* Multi-SVID fetch APIs and hint-based JWT SVID selection.
* Explicit Unix and TCP endpoint handling with strict validation.


## [0.7.4] – 2025-12-24

* Migrated to the Rust 2021 edition.
* Minimum supported Rust version (MSRV) is now 1.83.


## [0.7.3] – 2025-12-24

### Fixed

* Fixed compilation when building with --no-default-features.
* Correctly feature-gated public re-exports and error variants tied to optional dependencies.
* Prevented optional dependencies from being required in minimal builds.

## [0.7.2] – 2025-12-24

### Changed

* Moved protobuf code generation out of build scripts and into an explicit `xtask` workflow.
* Committed generated Workload API sources.

### Removed

* Removed build-time protobuf generation (`build.rs`) from the `spiffe` crate.


## [0.7.1] - 2025-12-23

### Added

* Added `JwtSvid::claims()` accessor to expose parsed JWT claims in a read-only, safe manner.
* Added `X509Source::x509_context()` convenience method to retrieve a snapshot of the current X.509 SVIDs and bundle set.

### Documentation

* Fixed doctest examples to correctly handle `Option`-returning APIs (`default_svid()`).
* Updated examples to use `bundle_set()` instead of non-existent `bundles()` accessor.
* Clarify `X509Source` as the primary entry point for X.509 workloads
* Improve overall structure and readability of crate-level docs

### Notes

* No breaking changes: existing APIs remain unchanged; additions are purely additive.


## [0.7.0] - 2025-12-23

### Added
- Automatic reconnection handling in `X509Source` when the SPIRE agent becomes unavailable and later recovers.

### Changed
- `X509Source::default()` has been replaced by `X509Source::new()` for clearer and more explicit construction.
- `X509Context` now includes federated bundles in addition to the trust domain bundle (#175).
- Updated `x509-parser` dependency from `0.17` to `0.18` (#171).
- Updated `jsonwebkey` dependency from `0.3` to `0.4` (#182).

### Breaking Changes
- The `X509Source` construction API has changed from `default()` to `new()`.

### Migration Notes
- Replace any usage of `X509Source::default()` with `X509Source::new()` when upgrading to v0.7.0.


## [0.6.7] - 2025-07-30

### What's Changed

* Bump tonic and prost dependencies to version 0.14 (#165)
* Bump protox dependency to 0.9.0 (#165)

## [0.6.6] - 2025-05-25

### What's Changed

* Bump tonic dependencies to version 0.13 (#144)
* Bump protox dependency to 0.8.0 (#151)

## [0.6.5] - 2025-03-04

### What's Changed

* Directly include generated Protobuf code from OUT_DIR (#138)

## [0.6.4] - 2025-01-31

### What's Changed
* Use protox to avoid the need to have protoc installed (#133)
* Bump Swatinem/rust-cache from 2.7.5 to 2.7.7 (#131)
* Bump coverallsapp/github-action from 2.3.4 to 2.3.6 (#134)
* Update x509-parser requirement from 0.16 to 0.17 (#135)
 
## [0.6.3] - 2024-11-07

### What's Changed

* Depend explicitly on tonic 0.12.3 (#120)
* Update thiserror requirement from 1 to 2 in (#127)

## [0.6.2] - 2024-10-07

### What's Changed
* Bump tonic dependencies to latest tonic release `0.12` by @howardjohn in https://github.com/maxlambrecht/rust-spiffe/pull/111
* Remove https://github.com/nhynes/jwk-rs as a runtime dependency by @bleggett in https://github.com/maxlambrecht/rust-spiffe/pull/115

## [0.6.1] - 2024-09-11

### What's Changed

- Update Rust Edition to 2021 (#82)
- Enhance Usability with Core Type Re-exports (#83)

## [0.5.0] - 2024-03-07

### Dependencies updates

- Updated `prost`, `prost-types`, and `prost-build` to "0.12" (#73)
- Updated `tonic` and `tonic-build` to "0.11" (#73)
- Updated `x509-parser` to "0.16" (#73)

## [0.4.0] - 2023-08-23

### Added

- Refactor of `spiffe` crate: Introduced `spiffe-types` and `workload-api` features for better modularity (#44).
- Implemented `X509Source` for fetching X.509 materials (#50).
- Added dependencies `log` and `tokio-util` specifically to the `workload-api` feature (#50, #51).

### API Changes

- Renamed `stream_` methods in `WorkloadApiClient` (#44).
- Moved `SocketPathError` and `GrpcClientError` to `spiffe::errors` package as part of the `spiffe-types` feature,
  aligning with the new structure (#44).

### Changed

- Replaced `unreachable!()` in `find_spiffe_id` function with `UnexpectedExtension` error variant to handle unexpected
  X.509 extensions, improving error handling in SAN extension parsing (#48).

## [0.3.1] - 2023-08-12

### Fixed

- Integrated `google/protobuf/Struct.proto` into the library, eliminating the need for other projects to rely on system
  versions of that file. This enhances compatibility across different build environments. (#36)

## [0.3.0] - 2023-08-08

### Breaking Changes
- **Workload API Client Update**: Methods' signatures have been transitioned from synchronous to asynchronous. They now require `&mut self` instead of `&self`.

### Added
- Support for watching and streaming updates for both X.509 and JWT SVIDs and Bundles.
- New integration tests covering the watch/stream functionalities.
- New dependencies: `tonic`, `prost`, `prost-types`, `tokio`, `tokio-stream`, and `tower`.

### Changed
- Code generation migrated from `protobuf` and `grpcio` to `tonic` and `prost`.

### Removed
- Dependencies: `protobuf`, `grpcio`, and `futures`.


## 0.2.2 (August 5, 2023)

  * Add `watch_x509_context_stream` method to `WorkloadApiClient` (#28)
  * Update `grpcio` to `0.12.0` (#27)
  * Update dependencies (#26)
  * Add error info to `grpcio:Error` (#25)

## 0.2.1 (April, 22, 2022)

  * Fix the chrono RUSTSEC advisory (#17)
  * Replace `chrono` by `time` crate.

## 0.2.0 (July 6, 2021)

  * Strict SPIFFE ID parsing (#8)
  * Method `validate_jwt_token` returns a `JwtSvid` parsed 
    from given token after validating it using then Workload API (#9)

## 0.1.1 (June 18, 2021)
  * Add method `validate_jwt_token` in the WorkloadApiClient (#2).

## 0.1.0 (June 14, 2021)

Initial implementation of the library (#1):
  * Workload API client with one-shot call methods
  * Certificate and PrivateKey types
  * X.509 SVID and bundle types
  * JWT SVID and bundle types
  * TrustDomain and SpiffeId types