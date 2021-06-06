//! X.509 bundle and JWT bundle types.

use crate::spiffe_id::TrustDomain;
use std::error::Error;

pub mod jwt;
pub mod x509;

/// Represents a collection of public keys.
pub trait Bundle {}

/// Represents a source of bundles queryable by [`TrustDomain`].
pub trait BundleSource {
    /// The type of the bundles provided by the source.
    type Item: Bundle;

    /// Returns the bundle (set of public keys authorities) associated to the [`TrustDomain`].
    /// If it cannot be found a bundle associated to the trust domain, it returns `Ok(None)`.
    /// If there's is an error in source fetching the bundle, it returns an `Err<Box<dyn Error + Send + 'static>>`.
    fn get_bundle_for_trust_domain(
        &self,
        trust_domain: &TrustDomain,
    ) -> Result<Option<&Self::Item>, Box<dyn Error + Send + 'static>>;
}
