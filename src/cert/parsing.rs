use crate::cert::errors::CertificateError;
use crate::cert::Certificate;
use x509_parser::certificate::X509Certificate;
use x509_parser::der_parser::oid::Oid;
use x509_parser::error::X509Error;
use x509_parser::extensions::ParsedExtension;
use x509_parser::nom::Err;
use x509_parser::nom::Err::Incomplete;

/// Takes a concatenated chain of DER encoded certificates and parses it
/// as a `Vec` of [`Certificate`].
pub(crate) fn to_certificate_vec(
    cert_chain_der: &[u8],
) -> Result<Vec<Certificate>, CertificateError> {
    let cert_der_blocks = asn1::from_der(cert_chain_der)?;

    let mut cert_chain = vec![];
    for block in cert_der_blocks.iter() {
        let cert_der = asn1::to_der(block)?;
        cert_chain.push(Certificate::from_der_bytes(cert_der));
    }
    Ok(cert_chain)
}

/// Try to parse the given DER-encoded slice of bytes as a X.509 certificate.
/// Returns a [`CertificateError`] if the the `der_bytes` is not DER-encoded or if
/// it cannot be parsed to a X.509 certificate.
pub(crate) fn parse_der_encoded_bytes_as_x509_certificate(
    der_bytes: &[u8],
) -> Result<X509Certificate<'_>, CertificateError> {
    let x509 = match x509_parser::parse_x509_certificate(der_bytes) {
        Ok(c) => c.1,
        Err(e) => {
            return Err(CertificateError::ParseX509Certificate(match e {
                Incomplete(_) => X509Error::InvalidCertificate,
                Err::Error(e) => e,
                Err::Failure(e) => e,
            }))
        }
    };
    Ok(x509)
}

// Returns the X.509 extension in the certificate the for the provided OID.
pub(crate) fn get_x509_extension<'a>(
    cert: &'a X509Certificate<'_>,
    oid: Oid<'a>,
) -> Result<&'a ParsedExtension<'a>, CertificateError> {
    let parsed_extension = match cert.tbs_certificate.get_extension_unique(&oid)? {
        None => return Err(CertificateError::MissingX509Extension(oid.to_string())),
        Some(s) => s.parsed_extension(),
    };
    Ok(parsed_extension)
}
