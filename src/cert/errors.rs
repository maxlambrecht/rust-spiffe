//! Type error for X.509 certificate parsing and validations.

use crate::spiffe_id::SpiffeIdError;
use asn1::{ASN1DecodeErr, ASN1EncodeErr};
use x509_parser::error::X509Error;

/// An error that may arise parsing and validating X.509 certificates.
#[derive(Debug, thiserror::Error, PartialEq)]
#[non_exhaustive]
pub enum CertificateError {
    /// 'CA' flag not allowed in leaf certificate.
    #[error("leaf certificate must not have CA flag set to true")]
    LeafCertificateHasCaFlag,

    /// 'cRLSign' not allowed as key usage in leaf certificate.
    #[error("leaf certificate must not have 'cRLSign' set as key usage")]
    LeafCertificateHasCrlSign,

    /// 'keyCertSign' not allowed as key usage in leaf certificate.
    #[error("leaf certificate must not have 'keyCertSign' set as key usage")]
    LeafCertificateHasKeyCertSign,

    /// 'digitalSignature' as key usage must be present in leaf certificate.
    #[error("leaf certificate must have 'digitalSignature' set as key usage")]
    LeafCertificatedNoDigitalSignature,

    /// 'CA' flag must be set in intermediate certificate.
    #[error("signing certificate must have CA flag set to true")]
    SigningCertificatedNoCa,

    /// 'keyCertSign' as key usage must be present in intermediate certificate.
    #[error("signing certificate must have 'keyCertSign' set as key usage")]
    SigningCertificatedNoKeyCertSign,

    /// An X.509 extension cannot be found.
    #[error("X.509 extension is missing: {0}")]
    MissingX509Extension(String),

    /// No URI Subject Alternative Names found.
    #[error("leaf certificate misses the SPIFFE-ID in the URI SAN")]
    MissingSpiffeId,

    /// The URI Subject Alternative Name is not a valid SPIFFE ID.
    #[error("failed parsing SPIFFE ID from certificate URI SAN")]
    InvalidSpiffeId(#[from] SpiffeIdError),

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
