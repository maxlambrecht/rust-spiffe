# Changelog

## [0.5.2] – 2026-01-21

### Changed

Updated spiffe dependency to 0.11.x, aligning with the latest SPIFFE core improvements and fixes.

## [0.5.1] – 2026-01-03

### Changed

- Updated `spiffe` dependency to `0.10` with `features = ["x509", "jwt", "transport-grpc"]`
- Removed feature `integration-tests`


## [0.5.0] – 2025-12-30

### Changed

- Updated dependency to **spiffe 0.9** using `default-features = false` and `features = ["transport"]`
- Delegated Identity client now returns `DelegatedIdentityError`
- **MSRV** bumped to Rust **1.85**


## [0.4.0] – 2025-12-26

### Changed

- Updated dependency to `spiffe` v0.8 with `grpc` enabled
- Replaced custom Unix domain socket connector with `spiffe::Endpoint` and the shared gRPC connector
- Updated `DelegatedIdentityClient` methods to take `&self` instead of `&mut self`

### Added

- New client constructors: `connect_env()`, `connect_to(...)`, and `connect(Endpoint)`

### Removed

- Removed custom transport plumbing and unused dependencies (`tower`, `hyper-util`)
- Dropped direct socket-path parsing in favor of typed endpoint parsing


## [0.3.9] – 2025-12-24

### Changed

- Migrated to the Rust 2021 edition
- Minimum supported Rust version (MSRV) is now 1.83


## [0.3.8] – 2025-12-24

### Changed

- Removed build-time protobuf generation (`build.rs`)
- Committed generated SPIRE API bindings
- Updated `spiffe` requirement to 0.7.3


## [0.3.7] – 2025-12-23

### Changed

- Updated `spiffe` requirement to 0.7.0


## [0.3.6] – 2025-07-30

### Changed

- Bumped `tonic` and `prost` dependencies to version 0.14 (#165)
- Bumped `protox` dependency to 0.9.0 (#165)
- Updated `spiffe` requirement to 0.6.7


## [0.3.5] – 2025-05-25

### Changed

- Bumped `tonic` dependencies to version 0.13 (#144)
- Bumped `protox` dependency to 0.8.0 (#151)


## [0.3.4] – 2025-03-04

### Changed

- Directly include generated Protobuf code from `OUT_DIR` (#138)


## [0.3.3] – 2025-01-31

### Changed

- Use `protox` to avoid the need to have `protoc` installed (#133)
- Updated `spiffe` requirement from 0.6.3 to 0.6.4
- Bumped `Swatinem/rust-cache` from 2.7.5 to 2.7.7 (#131)
- Bumped `coverallsapp/github-action` from 2.3.4 to 2.3.6 (#134)
- Updated `x509-parser` requirement from 0.16 to 0.17 (#135)


## [0.3.2] – 2024-11-07

### Changed

- Depend explicitly on `tonic 0.12.3` (#120)
- Updated `thiserror` requirement from `1` to `2` (#127)
- Depend on `spiffe 0.6.3`


## [0.3.1] – 2024-10-07

### Changed

- Bumped `tonic` dependencies to latest `0.12` (#111)
- Removed `jwk-rs` as a runtime dependency (#115)


## [0.3.0] – 2024-09-12

### Changed

- Updated Rust edition to 2021 (#82)
- Enhanced usability with core type re-exports (#83)
- Synced delegated API changes and bumped `spire-api-sdk` to 1.10.2 (#96)


## [0.2.0] – 2024-03-07

### Changed

- Updated `prost`, `prost-types`, and `prost-build` to 0.12 (#73)
- Updated `tonic` and `tonic-build` to 0.11 (#73)


## [0.1.0] – 2023-09-03

### Added

- SPIRE Delegated Identity API support (#43)
