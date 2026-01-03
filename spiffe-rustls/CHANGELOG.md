# Changelog

## [0.4.0] – 2026-01-03

### ⚠️ Breaking changes

- Public builders (`mtls_client`, `mtls_server`, `ClientConfigBuilder`, `ServerConfigBuilder`)
  now accept `X509Source` by value instead of `Arc<X509Source>`.

### Changed
- Observability macros emit events via tracing when the tracing feature is enabled,
  fall back to log when only the logging feature is enabled, and are no-ops when
  neither feature is enabled.


## [0.3.0] – 2025-12-30

### ⚠️ Breaking changes

* Authorization API redesigned
    * String-based authorization hooks have been replaced with a typed `Authorizer` trait operating on `SpiffeId`.
    * Existing authorization logic must be migrated to `Authorizer` implementations or helper constructors
      (`authorizer::any`, `authorizer::exact`, `authorizer::trust_domains`).

* Builder APIs reshaped
    * Client and server builders were updated to support trust domain policies and stricter verifier guarantees.
    * Method signatures and configuration flow have changed accordingly.

* MSRV bump
    * Minimum Supported Rust Version increased from 1.83 → 1.85.

### Added

* Federation-aware by default
    * Verifiers automatically handle multiple trust domains when SPIFFE federation is configured.
* Trust domain policy enforcement
    * New `TrustDomainPolicy` type with the following variants:
        * `AnyInBundleSet` (default)
        * `AllowList`
        * `LocalOnly`
    * Allows explicit restriction of accepted trust domains as a defense-in-depth mechanism.
* Typed authorization helpers
    * Strongly typed authorization helpers built on `SpiffeId`.
* Optional `tracing` and `loggin` support

### Changed

* Verifier hardening
    * Reject certificates containing multiple SPIFFE ID URI SANs.
    * Bound and validate URI SAN parsing.
    * Cache parsed certificate results to avoid repeated parsing.

* Improved TLS failure semantics
    * When trust domain policies exclude all trust domains, verification now fails with
      clear `TrustDomainNotAllowed` errors instead of opaque TLS handshake failures.

* Dependency updates
    * Bumped `spiffe` dependency to 0.9.

### Migration notes

* Replace string-based authorization logic with `Authorizer` implementations.
* Review trust domain behavior and configure `TrustDomainPolicy` explicitly if needed.
* Ensure toolchains are updated to Rust 1.85+.


## [0.2.0] – 2025-12-26

### Changed
- Updated dependency to `spiffe 0.8.0`.
- Made `ClientConfigBuilder::build()` and `ServerConfigBuilder::build()` synchronous (removed async/await).
- Refactored material construction to use `rustls::pki_types::CertificateDer` and renamed helpers for clarity.
- Added generation tracking to material snapshots and implemented verifier caching keyed by generation.
- Tightened crate linting and documentation policy (`missing_docs`, `unsafe_code`, clippy incl. `pedantic`).

### Fixed
- Improved internal correctness and performance under trust bundle rotation by avoiding verifier rebuilds on every handshake.

### Notes
- Building configs now requires a Tokio runtime to spawn the rotation watcher; initialization returns an error if no runtime is available.


## [0.1.3] – 2025-12-24

* Documentation improvements only. No functional changes.


## [0.1.2] – 2025-12-24

* Migrated to the Rust 2021 edition.
* Minimum supported Rust version (MSRV) is now 1.83.

## [0.1.1] – 2025-12-24

### Fixed
- Fixed handling of X.509 trust bundle rotation so that rustls trust roots are updated when bundles change.

### Changed
- Moved gRPC examples into a separate crate.
- Removed `build.rs` and gRPC-related build dependencies from the core crate.

## [0.1.0] – 2025-12-23

### Added
- Initial release of `spiffe-rustls`.
- Integration of SPIFFE X.509 identity with `rustls`.
- Support for dynamic SVID and trust bundle updates via `X509Source`.
