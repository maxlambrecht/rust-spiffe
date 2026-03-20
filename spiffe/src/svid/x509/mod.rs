//! X.509-SVID types.

mod validations;

use crate::cert::error::{CertificateError, PrivateKeyError};
use crate::cert::parsing::to_certificate_vec;
use crate::cert::{Certificate, PrivateKey};
use crate::spiffe_id::SpiffeId;
use crate::svid::x509::validations::{validate_leaf_certificate, validate_signing_certificates};
use std::convert::TryFrom as _;
use std::sync::Arc;

/// Represents a SPIFFE X.509-SVID.
///
/// Contains a [`SpiffeId`], a certificate chain as DER-encoded X.509 certificates,
/// and a private key as DER-encoded PKCS#8.
///
/// Use [`X509Svid::parse_from_der`] to create an SVID from DER-encoded data, or
/// obtain one from the [Workload API](crate::WorkloadApiClient) or [`X509Source`].
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct X509Svid {
    spiffe_id: SpiffeId,
    cert_chain: Vec<Certificate>,
    private_key: PrivateKey,
    hint: Option<Arc<str>>,
}

/// Errors that may arise parsing a [`X509Svid`] from a DER-encoded
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
    LeafCertificateMissingDigitalSignature,

    /// 'CA' flag must be set in intermediate certificate.
    #[error("signing certificate must have CA flag set to true")]
    SigningCertificateMissingCaFlag,

    /// 'keyCertSign' as key usage must be present in intermediate certificate.
    #[error("signing certificate must have 'keyCertSign' set as key usage")]
    SigningCertificateMissingKeyCertSign,

    /// Extension is present but could not be parsed.
    #[error("{extension} extension is present but could not be parsed")]
    UnparseableExtension {
        /// The name of the extension that failed to parse.
        extension: &'static str,
    },

    /// Error processing or validating the X.509 certificates.
    #[error(transparent)]
    Certificate(#[from] CertificateError),

    /// Error processing the private key.
    #[error(transparent)]
    PrivateKey(#[from] PrivateKeyError),
}

impl X509Svid {
    /// Creates a `X509Svid` from certificate chain and private key DER-encoded data.
    ///
    /// # Arguments
    /// * `cert_chain_der` - DER-encoded (concatenated) certificate chain (no padding between certs).
    /// * `private_key_der` - DER-encoded PKCS#8 private key.
    ///
    /// # Errors
    /// Returns [`X509SvidError`] if parsing or validation fails.
    pub fn parse_from_der(
        cert_chain_der: &[u8],
        private_key_der: &[u8],
    ) -> Result<Self, X509SvidError> {
        Self::parse_from_der_with_hint(cert_chain_der, private_key_der, None)
    }

    /// Creates a [`X509Svid`] from a certificate chain and private key, with an optional usage hint.
    ///
    /// The `hint` is an operator-provided string supplied by the SPIFFE Workload API
    /// to convey guidance on how the SVID should be used when multiple SVIDs are
    /// available (e.g. `"internal"`, `"external"`). The hint is optional and may be
    /// absent.
    ///
    /// # Arguments
    ///
    /// * `cert_chain_der` - DER-encoded (concatenated) X.509 certificate chain
    ///   (no padding between certificates).
    /// * `private_key_der` - DER-encoded PKCS#8 private key.
    /// * `hint` - Optional usage hint associated with this SVID.
    ///
    /// # Errors
    ///
    /// Returns [`X509SvidError`] if parsing or validation of the certificate chain
    /// or private key fails.
    pub fn parse_from_der_with_hint(
        cert_chain_der: &[u8],
        private_key_der: &[u8],
        hint: Option<Arc<str>>,
    ) -> Result<Self, X509SvidError> {
        let cert_chain = to_certificate_vec(cert_chain_der)?;

        let Some((leaf, rest)) = cert_chain.split_first() else {
            return Err(X509SvidError::EmptyChain);
        };

        let spiffe_id = validate_leaf_certificate(leaf)?;
        validate_signing_certificates(rest)?;
        let private_key = PrivateKey::try_from(private_key_der)?;

        Ok(Self {
            spiffe_id,
            cert_chain,
            private_key,
            hint,
        })
    }

    /// Returns the [`SpiffeId`] of the `X509Svid`.
    pub const fn spiffe_id(&self) -> &SpiffeId {
        &self.spiffe_id
    }

    /// Returns the certificate chain. The first certificate is the leaf certificate.
    pub fn cert_chain(&self) -> &[Certificate] {
        &self.cert_chain
    }

    /// Returns the leaf certificate.
    ///
    /// # Panics
    ///
    /// This method will panic if the certificate chain is empty. This should never
    /// happen with properly constructed `X509Svid` instances, as the constructor
    /// validates that the chain is non-empty.
    pub fn leaf(&self) -> &Certificate {
        #[expect(clippy::panic, reason = "documented behavior")]
        self.cert_chain
            .first()
            .unwrap_or_else(|| panic!("certificate chain is empty"))
    }

    /// Returns the private key.
    pub const fn private_key(&self) -> &PrivateKey {
        &self.private_key
    }

    /// Returns the optional hint provided by the Workload API.
    pub fn hint(&self) -> Option<&str> {
        self.hint.as_deref()
    }
}
