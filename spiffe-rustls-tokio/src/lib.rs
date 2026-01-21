#![deny(missing_docs)]
#![deny(unsafe_code)]
#![warn(missing_debug_implementations)]
#![warn(clippy::all)]
#![warn(clippy::pedantic)]
#![allow(clippy::module_name_repetitions)]
#![allow(clippy::must_use_candidate)]

//! # spiffe-rustls-tokio
//!
//! Tokio-native accept/connect helpers for [spiffe-rustls](https://docs.rs/spiffe-rustls) configs.
//!
//! This crate provides a small adapter layer that makes it easy to use SPIFFE mTLS
//! with Tokio + rustls and to extract peer identity from TLS connections.
//!
//! ## Features
//!
//! - **Tokio integration**: Native async accept/connect operations
//! - **Peer identity extraction**: Automatically extract SPIFFE IDs from peer certificates
//!
//! ## Examples
//!
//! Complete working examples are available in the `examples/` directory:
//!
//! - `mtls_tcp_server` - Server that accepts mTLS connections and extracts peer SPIFFE IDs
//! - `mtls_tcp_client` - Client that connects to the server and extracts peer SPIFFE IDs
//!
//! Run them with:
//!
//! ```bash
//! cargo run --package spiffe-rustls-tokio --example mtls_tcp_server
//! cargo run --package spiffe-rustls-tokio --example mtls_tcp_client
//! ```
//!
//! See the [README](https://github.com/maxlambrecht/rust-spiffe/blob/main/spiffe-rustls-tokio/README.md)
//! for detailed usage instructions.
//!
//! ## Peer Identity Extraction Semantics
//!
//! After a successful TLS handshake, the peer's SPIFFE ID is automatically extracted
//! from their certificate's URI SAN.
//!
//! ### SPIFFE X.509-SVID Expectations
//!
//! According to the SPIFFE specification, an X.509-SVID must contain **exactly one** SPIFFE ID
//! in the URI SAN, and peers are expected to present certificates when mTLS is required.
//! When using `spiffe-rustls` verifiers correctly, these requirements are enforced during
//! the TLS handshake, and the cases below should normally be unreachable.
//!
//! ### Observed API Behavior
//!
//! This crate performs post-handshake identity extraction from connections that have already passed TLS verification.
//! The API behavior is:
//!
//! - **Exactly one SPIFFE ID**: Extracted and stored in `PeerIdentity::spiffe_id`
//! - **Missing SPIFFE ID**: `PeerIdentity::spiffe_id` is `None` (`accept()`/`connect()` succeed)
//!   - **SPIFFE perspective**: Invalid X.509-SVID; indicative of misconfiguration or non-SPIFFE peer
//! - **Multiple SPIFFE IDs**: `PeerIdentity::spiffe_id` is `None` (`accept()`/`connect()` succeed)
//!   - **SPIFFE perspective**: Invalid X.509-SVID; indicative of misconfiguration or non-SPIFFE peer
//! - **No peer certificates**: `PeerIdentity::spiffe_id` is `None` (`accept()`/`connect()` succeed)
//!   - **SPIFFE perspective**: Invalid for mTLS; indicative of misconfiguration or non-SPIFFE peer
//! - **Certificate parse failure**: Returns `Error::CertParse` (`accept()`/`connect()` fail)
//!
//! **Note**: A `None` value for `spiffe_id` is unexpected in SPIFFE-compliant configurations
//! and may indicate that the TLS configuration is not enforcing SPIFFE semantics, or that
//! the peer is not presenting a valid SPIFFE X.509-SVID.

mod acceptor;
mod connector;
mod error;
mod identity;

pub use acceptor::TlsAcceptor;
pub use connector::TlsConnector;
pub use error::Error;
pub use identity::PeerIdentity;
