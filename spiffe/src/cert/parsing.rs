//! Internal parsing and validation helpers.

use crate::cert::error::CertificateError;
use crate::cert::Certificate;
use x509_parser::certificate::X509Certificate;
use x509_parser::der_parser::oid::Oid;
use x509_parser::error::X509Error;
use x509_parser::extensions::ParsedExtension;
use x509_parser::nom::Err;

/// Takes a concatenated chain of DER-encoded certificates and parses it
/// into a `Vec<Certificate>`.
pub(crate) fn to_certificate_vec(
    cert_chain_der: &[u8],
) -> Result<Vec<Certificate>, CertificateError> {
    let cert_der_blocks = asn1::from_der(cert_chain_der)?;

    let mut cert_chain = Vec::with_capacity(cert_der_blocks.len());
    for block in cert_der_blocks {
        let cert_der = asn1::to_der(&block)?;
        // We already have a DER block, but still validate it to uphold invariants.
        cert_chain.push(Certificate::from_der_bytes(cert_der)?);
    }

    Ok(cert_chain)
}

/// Parses the given DER-encoded bytes as an X.509 certificate.
///
/// Returns a [`CertificateError`] if the input is not a parseable DER-encoded X.509 certificate.
pub(crate) fn parse_der_encoded_bytes_as_x509_certificate(
    der_bytes: &[u8],
) -> Result<X509Certificate<'_>, CertificateError> {
    match x509_parser::parse_x509_certificate(der_bytes) {
        Ok((_, cert)) => Ok(cert),
        Err(Err::Incomplete(_)) => Err(CertificateError::ParseX509Certificate(
            X509Error::InvalidCertificate,
        )),
        Err(Err::Error(e) | Err::Failure(e)) => Err(CertificateError::ParseX509Certificate(e)),
    }
}

/// Returns the parsed X.509 extension for the provided OID.
///
/// # Errors
/// - [`CertificateError::MissingX509Extension`] if the extension is not present.
/// - [`CertificateError::ParseX509Certificate`] for underlying parsing issues.
pub(crate) fn get_x509_extension<'a>(
    cert: &'a X509Certificate<'_>,
    oid: &Oid<'a>,
) -> Result<&'a ParsedExtension<'a>, CertificateError> {
    match cert.tbs_certificate.get_extension_unique(oid)? {
        None => Err(CertificateError::MissingX509Extension(oid.to_string())),
        Some(ext) => Ok(ext.parsed_extension()),
    }
}
