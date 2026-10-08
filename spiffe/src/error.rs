//! Error types shared across SPIFFE APIs.

/// An error returned while decoding or encoding JSON.
///
/// The underlying error is available through [`std::error::Error::source`]
/// for diagnostics. Its concrete type and formatted message may change
/// between releases.
#[derive(Debug, thiserror::Error)]
#[error("{source}")]
pub struct JsonError {
    #[source]
    source: serde_json::Error,
}

impl JsonError {
    pub(crate) const fn new(source: serde_json::Error) -> Self {
        Self { source }
    }
}
