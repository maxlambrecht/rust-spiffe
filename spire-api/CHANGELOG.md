# Changelog

## [0.3.6] - 2025-07-30

### What's Changed

* Bump tonic and prost dependencies to version 0.14 (#165)
* Bump protox dependency to 0.9.0 (#165)
* Update spiffe requirement to 0.6.7

## [0.3.5] - 2025-05-25

### What's Changed

* Bump tonic dependencies to version 0.13 (#144)
* Bump protox dependency to 0.8.0 (#151)

## [0.3.4] - 2025-03-04

### What's Changed

* Directly include generated Protobuf code from OUT_DIR (#138)

## [0.3.3] - 2025-01-31

### What's Changed

* Use protox to avoid the need to have protoc installed (#133)
* Update spiffe requirement from 0.6.3 to 0.6.4
* Bump Swatinem/rust-cache from 2.7.5 to 2.7.7 (#131)
* Bump coverallsapp/github-action from 2.3.4 to 2.3.6 (#134)
* Update x509-parser requirement from 0.16 to 0.17 (#135)

## [0.3.2] - 2024-11-07

### What's Changed

* Depend explicitly on tonic `0.12.3` (#120)
* Update thiserror requirement from `1` to `2` in (#127)
* Depend on spiffe `0.6.3`

## [0.3.1] - 2024-10-07

### What's Changed
* Bump tonic dependencies to latest tonic release `0.12` by @howardjohn in https://github.com/maxlambrecht/rust-spiffe/pull/111
* Remove https://github.com/nhynes/jwk-rs as a runtime dependency by @bleggett in https://github.com/maxlambrecht/rust-spiffe/pull/115

## [0.3.0] - 2024-09-12

- Update Rust Edition to 2021 (#82)
- Enhance Usability with Core Type Re-exports (#83)
- Sync delegate api changes + `spire-api-sdk` bump to 1.10.2 (#96)
 
## [0.2.0] - 2024-03-07

### Dependencies updates

- Updated `prost`, `prost-types`, and `prost-build` to "0.12" (#73)
- Updated `tonic` and `tonic-build` to "0.11" (#73)

## [0.1.0] - 2023-09-03

### Added

- SPIRE Delegated Identity API support (#43).
