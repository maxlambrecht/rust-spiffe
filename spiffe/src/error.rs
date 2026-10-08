//! Error types shared across SPIFFE APIs.

/// An error returned while decoding or encoding JSON.
///
/// This wrapper is transparent. Formatting it formats the underlying JSON
/// error, and [`std::error::Error::source`] returns that error's source. The
/// underlying error type is not part of this crate's public API and may change
/// between releases.
#[derive(Debug, thiserror::Error)]
#[error(transparent)]
pub struct JsonError {
    source: serde_json::Error,
}

impl JsonError {
    pub(crate) const fn new(source: serde_json::Error) -> Self {
        Self { source }
    }
}
