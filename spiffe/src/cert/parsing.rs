//! Internal parsing and validation helpers.

use crate::cert::error::CertificateError;
use crate::cert::Certificate;
use crate::spiffe_id::SPIFFE_SCHEME_PREFIX;
use crate::SpiffeId;
use x509_parser::certificate::X509Certificate;
use x509_parser::der_parser::oid::Oid;
use x509_parser::error::X509Error;
use x509_parser::extensions::ParsedExtension;
use x509_parser::nom::Err;
use x509_parser::oid_registry;
use x509_parser::prelude::GeneralName;

const MAX_URI_SAN_ENTRIES: usize = 32;
const MAX_URI_LENGTH: usize = 2048;

/// Takes a concatenated chain of DER-encoded certificates and parses it
/// into a `Vec<Certificate>`.
pub(crate) fn to_certificate_vec(
    cert_chain_der: &[u8],
) -> Result<Vec<Certificate>, CertificateError> {
    let mut rest = cert_chain_der;
    let mut certs = Vec::new();

    while !rest.is_empty() {
        let (new_rest, _cert) = x509_parser::parse_x509_certificate(rest).map_err(|e| match e {
            Err::Incomplete(_) => {
                CertificateError::ParseX509Certificate(X509Error::InvalidCertificate)
            }
            Err::Error(err) | Err::Failure(err) => CertificateError::ParseX509Certificate(err),
        })?;

        // Extract the certificate bytes from the original input by calculating
        // the length of the certificate that was just parsed.
        let cert_len = rest.len() - new_rest.len();
        let cert_bytes = &rest[..cert_len];

        // Validate and store the original DER bytes
        certs.push(Certificate::try_from(cert_bytes)?);

        rest = new_rest;
    }

    Ok(certs)
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
    oid: &Oid<'static>,
) -> Result<&'a ParsedExtension<'a>, CertificateError> {
    match cert.tbs_certificate.get_extension_unique(oid)? {
        None => Err(CertificateError::MissingX509Extension(oid.clone())),
        Some(ext) => Ok(ext.parsed_extension()),
    }
}

pub(crate) fn extract_spiffe_ids_from_uri_san(
    cert: &X509Certificate<'_>,
) -> Result<Vec<SpiffeId>, CertificateError> {
    let ext = get_x509_extension(cert, &oid_registry::OID_X509_EXT_SUBJECT_ALT_NAME)?;

    let san = match ext {
        ParsedExtension::SubjectAlternativeName(s) => s,
        other => return Err(CertificateError::UnexpectedExtension(format!("{other:?}"))),
    };

    // Conservative preallocation. Usually 0–1 in practice.
    let mut ids = Vec::new();

    let mut uri_count = 0usize;
    for name in &san.general_names {
        let uri = match name {
            GeneralName::URI(u) => *u,
            _ => continue,
        };

        uri_count += 1;
        if uri_count > MAX_URI_SAN_ENTRIES {
            return Err(CertificateError::TooManyUriSanEntries {
                max: MAX_URI_SAN_ENTRIES,
            });
        }

        // Skip large junk without allocating/parsing.
        if uri.len() > MAX_URI_LENGTH {
            continue;
        }

        if !uri.starts_with(SPIFFE_SCHEME_PREFIX) {
            continue;
        }

        // Strict: any spiffe:// URI must be valid.
        ids.push(SpiffeId::new(uri)?);
    }

    Ok(ids)
}
