# Changelog

## [0.1.2] – 2026-02-14

### Changed
- MSRV raised to 1.88 (inherited from workspace; required by `spiffe` 0.11.4).
- Moved `spiffe-rustls` from runtime dependency to dev-dependency (only used in examples).
- Workspace lints now inherited via `[lints] workspace = true`.
- Resolved clippy lints and tightened rustdoc.

### Notes
- No public API changes.


## [0.1.1] – 2026-01-22

### Changed
- Tightened README and crate-level documentation for clarity and consistency; no functional changes.

## [0.1.0] – 2026-01-21

### Added

- Initial release of `spiffe-rustls-tokio`
- `TlsAcceptor` for server-side TLS connections with post-handshake peer identity extraction
- `TlsConnector` for client-side TLS connections with post-handshake peer identity extraction
- `PeerIdentity` struct for accessing extracted SPIFFE IDs from peer certificates
- `connect_addr()` convenience method that combines TCP connection and TLS handshake
- Complete working examples (`mtls_tcp_server` and `mtls_tcp_client`) demonstrating real mTLS connections with SPIRE

### Notes

- This crate provides a small adapter layer over `tokio-rustls`, operating on already-verified TLS connections created with `spiffe-rustls`
- Peer identity extraction occurs **after a successful TLS handshake**
- Peer identity extraction errors occur only on certificate parse failures; missing or multiple SPIFFE IDs result in `PeerIdentity::spiffe_id = None` (no error)
- In SPIFFE-compliant configurations, certificates are expected to contain exactly one SPIFFE ID; `None` typically indicates misconfiguration or a non-SPIFFE peer
