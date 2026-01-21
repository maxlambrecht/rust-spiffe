//! Error types for `spiffe-rustls-tokio`.

use thiserror::Error;

/// Errors returned by `spiffe-rustls-tokio`.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum Error {
    /// A rustls error occurred.
    ///
    /// This typically occurs during the TLS handshake, but can also occur
    /// during connection operations.
    #[error("rustls error: {0}")]
    Rustls(#[from] tokio_rustls::rustls::Error),

    /// Failed to parse a peer certificate.
    ///
    /// This error occurs when the peer certificate cannot be parsed after a
    /// successful TLS handshake. Note that missing or multiple SPIFFE IDs do
    /// not cause this error; they result in `PeerIdentity::spiffe_id` being
    /// `None`.
    #[error("failed parsing peer certificate: {0}")]
    CertParse(String),

    /// The peer certificate does not contain a SPIFFE ID in the URI SAN.
    ///
    /// This error is returned by `PeerIdentity::require_spiffe_id()` when
    /// `spiffe_id` is `None`. This is distinct from `CertParse`, which indicates
    /// an actual certificate parsing failure.
    #[error("peer certificate missing SPIFFE ID in URI SAN")]
    MissingSpiffeId,

    /// An I/O error occurred.
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
}
