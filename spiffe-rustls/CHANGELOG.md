# Changelog

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
