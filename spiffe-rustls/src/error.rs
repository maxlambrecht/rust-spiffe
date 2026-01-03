use spiffe::SpiffeId;

/// Result type used by this crate.
pub type Result<T> = std::result::Result<T, Error>;

/// Errors returned by `spiffe-rustls`.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    /// The `X509Source` currently has no SVID.
    #[error("x509 source has no current SVID")]
    NoSvid,

    /// The `X509Source` is closed or cancelled.
    #[error("x509 source is closed")]
    SourceClosed,

    /// The `X509Source` currently has no bundle for the requested trust domain.
    #[error("x509 source has no bundle for trust domain {0}")]
    NoBundle(spiffe::TrustDomain),

    /// The trust domain is not allowed by the trust domain policy.
    #[error("trust domain {0} is not allowed by policy")]
    TrustDomainNotAllowed(spiffe::TrustDomain),

    /// Failed to construct an authorizer due to invalid configuration.
    #[error("authorizer configuration error: {0}")]
    AuthorizerConfig(#[from] AuthorizerConfigError),

    /// Failed to create a `rustls::sign::CertifiedKey` from SVID material.
    #[error("failed building rustls certified key: {0}")]
    CertifiedKey(String),

    /// Failed to parse a peer certificate.
    #[error("failed parsing peer certificate: {0}")]
    CertParse(String),

    /// The peer certificate is missing a SPIFFE ID URI SAN.
    #[error("peer is missing SPIFFE ID URI SAN")]
    MissingSpiffeId,

    /// The peer certificate has multiple SPIFFE ID URI SANs (invalid).
    #[error("peer certificate has multiple SPIFFE ID URI SANs")]
    MultipleSpiffeIds,

    /// The peer SPIFFE ID was rejected by the authorization hook.
    #[error("peer SPIFFE ID is not authorized: {0}")]
    UnauthorizedSpiffeId(SpiffeId),

    /// Failed to build a rustls verifier.
    #[error("rustls verifier builder error: {0}")]
    VerifierBuilder(String),

    /// A rustls error occurred.
    #[error("rustls error: {0}")]
    Rustls(#[from] rustls::Error),

    /// An error from the underlying `X509Source`.
    #[error("x509 source error: {0}")]
    Source(#[from] spiffe::x509_source::X509SourceError),

    /// Internal error.
    #[error("internal: {0}")]
    Internal(String),

    /// Tokio runtime is required but not available in the current context.
    #[error("tokio runtime is required but not available in the current context")]
    NoTokioRuntime,

    /// No root certificates were accepted into a root certificate store.
    ///
    /// This occurs when building a root certificate store from a trust bundle
    /// and none of the provided certificates are valid or accepted by rustls.
    #[error("no root certificates were accepted into root certificate store")]
    EmptyRootStore,

    /// No usable root certificate stores could be built from any trust domain bundle.
    ///
    /// This occurs when `build_material` iterates through all trust domain bundles
    /// in the bundle set and fails to build a valid root certificate store for any of them.
    /// This is distinct from `EmptyRootStore`, which indicates a failure for a single
    /// trust domain bundle.
    #[error("no usable root certificate stores could be built from any trust domain bundle")]
    NoUsableRootStores,
}

/// Errors that occur when constructing an authorizer with invalid configuration.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum AuthorizerConfigError {
    /// A SPIFFE ID in the configuration is invalid.
    #[error("invalid SPIFFE ID: {0}")]
    InvalidSpiffeId(String),

    /// A trust domain in the configuration is invalid.
    #[error("invalid trust domain: {0}")]
    InvalidTrustDomain(String),
}
