//! `Certificate` and `PrivateKey` types and helpers.
//!
//! These types wrap DER-encoded bytes and validate them at construction time.

use crate::cert::error::{CertificateError, PrivateKeyError};
use crate::cert::parsing::parse_der_encoded_bytes_as_x509_certificate;
use pkcs8::PrivateKeyInfo;
use std::convert::TryFrom;
use zeroize::Zeroize;

pub mod error;
pub(crate) mod parsing;

/// A single DER-encoded X.509 certificate.
///
/// Invariant: instances are always validated as parseable DER-encoded X.509.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct Certificate(Vec<u8>);

impl Certificate {
    /// Returns the certificate bytes.
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// Constructs a certificate from DER bytes, validating them.
    pub(crate) fn from_der_bytes(bytes: Vec<u8>) -> Result<Self, CertificateError> {
        parse_der_encoded_bytes_as_x509_certificate(&bytes)?;
        Ok(Self(bytes))
    }
}
impl AsRef<[u8]> for Certificate {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl TryFrom<&[u8]> for Certificate {
    type Error = CertificateError;

    fn try_from(der_bytes: &[u8]) -> Result<Self, Self::Error> {
        parse_der_encoded_bytes_as_x509_certificate(der_bytes)?;
        Ok(Self(Vec::from(der_bytes)))
    }
}

impl TryFrom<Vec<u8>> for Certificate {
    type Error = CertificateError;

    fn try_from(der_bytes: Vec<u8>) -> Result<Self, Self::Error> {
        parse_der_encoded_bytes_as_x509_certificate(&der_bytes)?;
        Ok(Self(der_bytes))
    }
}

/// A DER-encoded private key in PKCS#8 format.
///
/// Invariant: instances are always validated as parseable PKCS#8.
///
/// This type is zeroized on drop.
#[derive(Debug, Clone, Eq, PartialEq, Zeroize)]
#[zeroize(drop)]
pub struct PrivateKey(Vec<u8>);

impl PrivateKey {
    /// Returns the private key bytes.
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

impl AsRef<[u8]> for PrivateKey {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl TryFrom<&[u8]> for PrivateKey {
    type Error = PrivateKeyError;

    fn try_from(bytes: &[u8]) -> Result<Self, Self::Error> {
        // Validate that the bytes are a valid PKCS#8 private key.
        PrivateKeyInfo::try_from(bytes).map_err(PrivateKeyError::DecodePkcs8)?;
        Ok(Self(Vec::from(bytes)))
    }
}

impl TryFrom<Vec<u8>> for PrivateKey {
    type Error = PrivateKeyError;

    fn try_from(bytes: Vec<u8>) -> Result<Self, Self::Error> {
        // Validate that the bytes are a valid PKCS#8 private key.
        PrivateKeyInfo::try_from(bytes.as_slice()).map_err(PrivateKeyError::DecodePkcs8)?;
        Ok(Self(bytes))
    }
}
