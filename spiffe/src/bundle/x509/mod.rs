//! X.509 bundle types.

use crate::cert::error::CertificateError;
use crate::cert::parsing::to_certificate_vec;
use crate::cert::Certificate;
use crate::spiffe_id::TrustDomain;
use crate::BundleSource;
use std::collections::HashMap;
use std::convert::Infallible;
use std::sync::Arc;

/// This type contains a collection of trusted X.509 authorities for a [`TrustDomain`].
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct X509Bundle {
    trust_domain: TrustDomain,
    x509_authorities: Vec<Certificate>,
}

/// This type contains a set of [`X509Bundle`], keyed by [`TrustDomain`].
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct X509BundleSet {
    bundles: HashMap<TrustDomain, Arc<X509Bundle>>,
}

/// An error that can arise trying to parse a [`X509Bundle`] from bytes
/// representing DER-encoded X.509 authorities.
#[derive(Debug, thiserror::Error, PartialEq)]
#[non_exhaustive]
pub enum X509BundleError {
    /// Error processing or validating the X.509 certificates in the bundle.
    #[error(transparent)]
    Certificate(#[from] CertificateError),
}

impl X509Bundle {
    /// Creates an empty `X509Bundle` for the given [`TrustDomain`].
    pub fn new(trust_domain: TrustDomain) -> Self {
        Self {
            trust_domain,
            x509_authorities: Vec::new(),
        }
    }

    /// Creates a bundle from a list of DER-encoded X.509 authorities.
    ///
    /// # Errors
    ///
    /// If the function cannot parse the inputs, a [`X509BundleError`] variant will be returned.
    pub fn from_x509_authorities(
        trust_domain: TrustDomain,
        authorities: &[&[u8]],
    ) -> Result<Self, X509BundleError> {
        let x509_authorities = authorities
            .iter()
            .map(|b| Certificate::try_from(*b))
            .collect::<Result<Vec<_>, _>>()?;

        Ok(Self {
            trust_domain,
            x509_authorities,
        })
    }

    /// Parses a bundle from ASN.1 DER-encoded data representing a concatenated list of certificates.
    ///
    /// # Errors
    ///
    /// If the function cannot parse the inputs, a [`X509BundleError`] variant will be returned.
    pub fn parse_from_der(
        trust_domain: TrustDomain,
        bundle_der: &[u8],
    ) -> Result<Self, X509BundleError> {
        let x509_authorities = to_certificate_vec(bundle_der)?;

        Ok(Self {
            trust_domain,
            x509_authorities,
        })
    }

    /// Adds an X.509 authority as ASN.1 DER-encoded data (binary format)to the bundle.
    /// It verifies that the `authorities_bytes` represents a valid DER-encoded X.509 certificate.
    ///
    /// # Arguments
    ///
    /// * `authority_bytes` - ASN.1 DER-encoded data (binary format) representing a X.509 authority.
    ///
    /// # Errors
    ///
    /// If the function cannot parse the inputs, a [`X509BundleError`] variant will be returned.
    pub fn add_authority(&mut self, authority_bytes: &[u8]) -> Result<(), X509BundleError> {
        let certificate = Certificate::try_from(authority_bytes)?;
        self.x509_authorities.push(certificate);
        Ok(())
    }

    /// Returns the [`TrustDomain`] associated with the bundle.
    pub fn trust_domain(&self) -> &TrustDomain {
        &self.trust_domain
    }

    /// Returns the X.509 authorities in the bundle.
    pub fn authorities(&self) -> &[Certificate] {
        &self.x509_authorities
    }
}

impl X509BundleSet {
    /// Creates a new empty `X509BundleSet`.
    pub fn new() -> Self {
        Self {
            bundles: HashMap::new(),
        }
    }

    /// Adds a new [`X509Bundle`] into the set. If a bundle already exists for the
    /// trust domain, the existing bundle is replaced.
    pub fn add_bundle(&mut self, bundle: X509Bundle) {
        let trust_domain = bundle.trust_domain().clone();
        self.bundles.insert(trust_domain, Arc::new(bundle));
    }

    /// Returns the [`X509Bundle`] associated with the given [`TrustDomain`].
    pub fn bundle_for(&self, trust_domain: &TrustDomain) -> Option<&Arc<X509Bundle>> {
        self.bundles.get(trust_domain)
    }
}

impl Default for X509BundleSet {
    fn default() -> Self {
        Self::new()
    }
}

impl BundleSource for X509BundleSet {
    type Item = X509Bundle;
    type Error = Infallible;

    fn bundle_for_trust_domain(
        &self,
        trust_domain: &TrustDomain,
    ) -> Result<Option<Arc<Self::Item>>, Self::Error> {
        Ok(self.bundles.get(trust_domain).cloned())
    }
}
