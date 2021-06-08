//! X.509-SVID and JWT-SVID types.

use std::error::Error;

pub mod jwt;
pub mod x509;

/// Represents a SPIFFE Verifiable Identity Document (SVID).
pub trait Svid {}

/// Represents a source of SPIFFE SVIDs.
pub trait SvidSource {
    /// The type of the SVIDs provided by the source.
    type Item: Svid;

    /// Returns an owned SVID.
    /// If it cannot be found an SVID in the source, it returns `Ok(None)`.
    /// If there's is an error in source fetching the SVID, it returns an `Err<Box<dyn Error + Send + Sync + 'static>>`.
    fn get_svid(&self) -> Result<Option<Self::Item>, Box<dyn Error + Send + Sync + 'static>>;
}

/// Represents a source of SPIFFE SVIDs.
pub trait SvidRefSource {
    /// The type of the SVIDs provided by the source.
    type Item: Svid;

    /// Returns an SVID reference.
    /// If it cannot be found an SVID in the source, it returns `Ok(None)`.
    /// If there's is an error in source fetching the SVID, it returns an `Err<Box<dyn Error + Send + Sync + 'static>>`.
    fn get_svid_ref(&self) -> Result<Option<&Self::Item>, Box<dyn Error + Send + Sync + 'static>>;
}
