//! X.509 bundle types.

use crate::bundle::{Bundle, BundleSource};
use crate::cert::errors::CertificateError;
use crate::cert::parsing::{parse_der_encoded_bytes_as_x509_certificate, to_certificate_vec};
use crate::cert::Certificate;
use crate::spiffe_id::TrustDomain;
use std::collections::HashMap;
use std::convert::TryFrom;
use std::error::Error;

/// This type contains a collection of trusted X.509 authorities for a [`TrustDomain`].
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct X509Bundle {
    trust_domain: TrustDomain,
    x509_authorities: Vec<Certificate>,
}

impl Bundle for X509Bundle {}

/// This type contains a set of [`X509Bundle`], keyed by [`TrustDomain`].
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct X509BundleSet {
    bundles: HashMap<TrustDomain, X509Bundle>,
}

/// An error that can arise trying to parse a [`X509Bundle`] from bytes
/// representing `DER` encoded X.509 authorities.
#[derive(Debug, thiserror::Error, PartialEq)]
#[non_exhaustive]
pub enum X509BundleError {
    /// Error processing or validating the X.509 certificates in the bundle.
    #[error(transparent)]
    Certificate(#[from] CertificateError),
}

impl X509Bundle {
    /// Creates an emtpy `X509Bundle` for the given [`TrustDomain`].
    pub fn new(trust_domain: TrustDomain) -> Self {
        X509Bundle {
            trust_domain,
            x509_authorities: Vec::new(),
        }
    }

    /// Creates a bundle from a slice of X.509 authorities as ASN.1 DER-encoded data (binary format).
    ///
    /// # Arguments
    ///
    /// * `authorities` - ASN.1 DER-encoded data (binary format) representing a list X.509 authorities.
    ///
    /// # Error
    ///
    /// If the function cannot parse the inputs, a [`X509BundleError`] variant will be returned.
    pub fn from_x509_authorities(
        trust_domain: TrustDomain,
        authorities: &[&[u8]],
    ) -> Result<Self, X509BundleError> {
        let mut x509_authorities = vec![];
        for authority in authorities
            .iter()
            .map(|&bytes| Certificate::try_from(bytes))
        {
            x509_authorities.push(authority?);
        }

        Ok(X509Bundle {
            trust_domain,
            x509_authorities,
        })
    }

    /// Parses a bundle from ASN.1 DER-encoded data (binary format) representing a list of X.509 authorities.
    ///
    /// # Arguments
    ///
    /// * `trust_domain` - A [`TrustDomain`] to associate to the bundle.
    /// * `bundle_der` - ASN.1 DER-encoded data (binary format) representing a list of X.509 authorities.
    ///
    /// # Error
    ///
    /// If the function cannot parse the inputs, a [`X509BundleError`] variant will be returned.
    pub fn parse_from_der(
        trust_domain: TrustDomain,
        bundle_der: &[u8],
    ) -> Result<Self, X509BundleError> {
        let x509_authorities = to_certificate_vec(bundle_der)?;

        // validate that all authorities are valid X.509 certificates
        for authority in x509_authorities.iter() {
            parse_der_encoded_bytes_as_x509_certificate(authority.content())?;
        }

        Ok(X509Bundle {
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
    /// # Error
    ///
    /// If the function cannot parse the inputs, a [`X509BundleError`] variant will be returned.
    pub fn add_authority(&mut self, authority_bytes: &[u8]) -> Result<(), X509BundleError> {
        let certificate = Certificate::try_from(authority_bytes)?;
        self.x509_authorities.push(certificate);
        Ok(())
    }

    /// Returns the [`TrustDomain`]associated to the bundle.
    pub fn trust_domain(&self) -> &TrustDomain {
        &self.trust_domain
    }

    /// Returns the X.509 authorities in the bundle.
    pub fn authorities(&self) -> &Vec<Certificate> {
        &self.x509_authorities
    }
}

impl X509BundleSet {
    /// Creates a new empty `X509BundleSet`.
    pub fn new() -> Self {
        X509BundleSet {
            bundles: HashMap::new(),
        }
    }

    /// Adds a new [`X509Bundle`] into the set. If a bundle already exists for the
    /// trust domain, the existing bundle is replaced.
    pub fn add_bundle(&mut self, bundle: X509Bundle) {
        self.bundles.insert(bundle.trust_domain().clone(), bundle);
    }

    /// Returns the [`X509Bundle`] associated to the given [`TrustDomain`].
    pub fn get_bundle(&self, trust_domain: &TrustDomain) -> Option<&X509Bundle> {
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

    /// Returns the [`X509Bundle`] associated to the given [`TrustDomain`].
    fn get_bundle_for_trust_domain(
        &self,
        trust_domain: &TrustDomain,
    ) -> Result<Option<&Self::Item>, Box<dyn Error + Send + 'static>> {
        Ok(self.bundles.get(trust_domain))
    }
}
