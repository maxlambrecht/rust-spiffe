//! Type error for X.509 certificate parsing and validations.

use asn1::{ASN1DecodeErr, ASN1EncodeErr};
use x509_parser::error::X509Error;

/// An error that may arise parsing and validating X.509 certificates.
#[derive(Debug, thiserror::Error, PartialEq)]
#[non_exhaustive]
pub enum CertificateError {
    /// An X.509 extension cannot be found.
    #[error("X.509 extension is missing: {0}")]
    MissingX509Extension(String),

    /// Unexpected X.509 extension encountered.
    #[error("unexpected X.509 extension: {0}")]
    UnexpectedExtension(String),

    /// Error returned by the ASN.1/DER processing library.
    #[error("failed decoding chain of DER certificates")]
    ChainDecode(#[from] ASN1DecodeErr),

    /// Error returned by the ASN.1/DER processing library.
    #[error("failed parsing DER certificate")]
    ParseDer(#[from] ASN1EncodeErr),

    /// Error returned by the X.509 parsing library.
    #[error("failed parsing X.509 certificate")]
    ParseX509Certificate(#[from] X509Error),
}

/// An error that may arise decoding private keys.
#[derive(Debug, thiserror::Error, PartialEq)]
#[non_exhaustive]
pub enum PrivateKeyError {
    /// Error returned by the pkcs#8 private key decoding library.
    #[error("failed decoding PKCS#8 private key")]
    DecodePkcs8(pkcs8::Error),
}
