# Changelog

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
