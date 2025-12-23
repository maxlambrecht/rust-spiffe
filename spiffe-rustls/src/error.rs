/// Result type used by this crate.
pub type Result<T> = std::result::Result<T, Error>;

/// Errors returned by `spiffe-rustls`.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// The `X509Source` currently has no SVID.
    #[error("x509 source has no current SVID")]
    NoSvid,

    /// The `X509Source` currently has no bundle for the requested trust domain.
    #[error("x509 source has no bundle for trust domain {0}")]
    NoBundle(String),

    /// Failed to create a `rustls::sign::CertifiedKey` from SVID material.
    #[error("failed building rustls certified key: {0}")]
    CertifiedKey(String),

    /// Failed to parse a peer certificate.
    #[error("failed parsing peer certificate: {0}")]
    CertParse(String),

    /// The peer certificate is missing a SPIFFE ID URI SAN.
    #[error("peer is missing SPIFFE ID URI SAN")]
    MissingSpiffeId,

    /// The peer SPIFFE ID was rejected by the authorization hook.
    #[error("peer SPIFFE ID is not authorized: {0}")]
    UnauthorizedSpiffeId(String),

    /// Failed to build a rustls verifier.
    #[error("rustls verifier builder error: {0}")]
    VerifierBuilder(String),

    /// A rustls error occurred.
    #[error("rustls error: {0}")]
    Rustls(#[from] rustls::Error),

    /// Internal error.
    #[error("internal: {0}")]
    Internal(String),
}
