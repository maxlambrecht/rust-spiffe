//! Error types for `spiffe-rustls-tokio`.

use thiserror::Error;

/// Errors returned by `spiffe-rustls-tokio`.
#[expect(clippy::error_impl_error, reason = "unfortunate public API")]
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum Error {
    /// A rustls error occurred.
    ///
    /// This typically occurs during the TLS handshake, but can also occur
    /// during connection operations.
    #[error("rustls error: {0}")]
    Rustls(#[from] rustls::Error),

    /// Peer certificate or SPIFFE identity parsing failed after the handshake.
    ///
    /// This includes a missing SAN extension or multiple URI SAN entries.
    /// See [`crate::PeerIdentity`] for the extraction outcomes.
    #[error("failed parsing peer certificate: {0}")]
    CertParse(String),

    /// No SPIFFE ID was extracted.
    ///
    /// Returned by [`crate::PeerIdentity::require_spiffe_id`] when the extracted
    /// identity is absent.
    #[error("peer certificate missing SPIFFE ID in URI SAN")]
    MissingSpiffeId,

    /// An I/O error occurred.
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
}
