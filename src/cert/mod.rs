//! Certificate and PrivateKey types and functions.

use crate::cert::errors::{CertificateError, PrivateKeyError};
use crate::cert::parsing::parse_der_encoded_bytes_as_x509_certificate;
use pkcs8::PrivateKeyInfo;
use std::convert::TryFrom;
use zeroize::Zeroize;

pub mod errors;
pub(crate) mod parsing;

/// This type contains a single certificate by value.
///
/// The certificate is a DER-encoded (binary format) X.509.
///
/// When an instance is created, it is checked that the bytes
/// represent a parseable DER-encoded X.509 certificate.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct Certificate(Vec<u8>);

impl Certificate {
    /// Returns the content of the certificate as a slice of bytes.
    pub fn content(&self) -> &[u8] {
        &self.0
    }

    pub(crate) fn from_der_bytes(bytes: Vec<u8>) -> Self {
        Self(bytes)
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

/// This type contains a private key by value.
///
/// The private key is be DER-encoded (binary format) ASN.1 in PKCS#8 format.
///
/// The struct is zeroized on drop.
#[derive(Debug, Clone, Eq, PartialEq, Zeroize)]
#[zeroize(drop)]
pub struct PrivateKey(Vec<u8>);

impl PrivateKey {
    /// Returns the content of the private key as a slice of bytes.
    pub fn content(&self) -> &[u8] {
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
        // validate that the bytes are a valid private key
        PrivateKeyInfo::try_from(bytes).map_err(PrivateKeyError::DecodePkcs8)?;
        Ok(Self(Vec::from(bytes)))
    }
}

impl TryFrom<Vec<u8>> for PrivateKey {
    type Error = PrivateKeyError;

    fn try_from(bytes: Vec<u8>) -> Result<Self, Self::Error> {
        // validate that the bytes are a valid private key
        PrivateKeyInfo::try_from(bytes.as_slice()).map_err(PrivateKeyError::DecodePkcs8)?;
        Ok(Self(bytes))
    }
}
