//! X.509-SVID types.

mod validations;

use crate::cert::errors::{CertificateError, PrivateKeyError};
use crate::cert::parsing::to_certificate_vec;
use crate::cert::{Certificate, PrivateKey};
use crate::spiffe_id::{SpiffeId, SpiffeIdError};
use crate::svid::x509::validations::{validate_leaf_certificate, validate_signing_certificates};
use crate::svid::Svid;
use std::convert::TryFrom;

/// This type represents a [SPIFFE X509-SVID](https://github.com/spiffe/spiffe/blob/main/standards/X509-SVID.md).
///
/// Contains a [`SpiffeId`], a certificate chain as a vec of DER-encoded X.509 certificates,
/// and a private key as a DER-encoded ASN.1 in PKCS#8 format.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct X509Svid {
    spiffe_id: SpiffeId,
    cert_chain: Vec<Certificate>,
    private_key: PrivateKey,
}

impl Svid for X509Svid {}

/// An error that may arise trying to parse a [`X509Svid`] from a `DER` encoded
/// chain of certificates and private key.
#[derive(Debug, thiserror::Error, PartialEq)]
#[non_exhaustive]
pub enum X509SvidError {
    /// The chain of certificates is empty.
    #[error("no certificates found in chain")]
    EmptyChain,

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

    /// No URI Subject Alternative Names found.
    #[error("leaf certificate misses the SPIFFE-ID in the URI SAN")]
    MissingSpiffeId,

    /// The URI Subject Alternative Name is not a valid SPIFFE ID.
    #[error("failed parsing SPIFFE ID from certificate URI SAN")]
    InvalidSpiffeId(#[from] SpiffeIdError),

    /// Error processing or validating the X.509 certificates.
    #[error(transparent)]
    Certificate(#[from] CertificateError),

    /// Error processing the private key.
    #[error(transparent)]
    PrivateKey(#[from] PrivateKeyError),
}

impl X509Svid {
    /// Creates a `X509Svid` from certificate chain and key ASN.1 DER-encoded data (binary format).
    ///
    /// # Arguments
    ///
    /// * `cert_chain_der` - Slice of bytes representing a chain of certificates as ASN.1 DER-encoded (concatenated
    /// with no intermediate padding if there are more than one certificate).
    ///
    /// * `private_key_der` - Slice of bytes representing a private key as ASN.1 DER in PKCS#8 format.
    ///
    /// # Errors
    ///
    /// If the function cannot parse the inputs, a [`X509SvidError`] variant will be returned.
    pub fn parse_from_der(
        cert_chain_der: &[u8],
        private_key_der: &[u8],
    ) -> Result<Self, X509SvidError> {
        let cert_chain = to_certificate_vec(cert_chain_der)?;

        let leaf = match cert_chain.first() {
            None => return Err(X509SvidError::EmptyChain),
            Some(c) => c,
        };

        let spiffe_id = validate_leaf_certificate(leaf)?;
        validate_signing_certificates(&cert_chain[1..])?;
        let private_key = PrivateKey::try_from(private_key_der)?;

        Ok(X509Svid {
            spiffe_id,
            cert_chain,
            private_key,
        })
    }

    /// Returns the [`SpiffeId`] of the `X509Svid`.
    pub fn spiffe_id(&self) -> &SpiffeId {
        &self.spiffe_id
    }

    /// Returns the chain of [`Certificate`] of the `X509Svid`. The first certificate in the
    /// chain is the leaf certificate.
    pub fn cert_chain(&self) -> &Vec<Certificate> {
        &self.cert_chain
    }

    /// Returns the leaf certificate of the chain.
    pub fn leaf(&self) -> &Certificate {
        &self.cert_chain[0]
    }

    /// Returns the private key of the `X509Svid`.
    pub fn private_key(&self) -> &PrivateKey {
        &self.private_key
    }
}
