//! Validation functions for leaf and intermediate(signing CA) certificates.

use crate::cert::errors::CertificateError;
use crate::cert::parsing::parse_der_encoded_bytes_as_x509_certificate;
use crate::cert::Certificate;
use crate::spiffe_id::SpiffeId;
use std::convert::TryFrom;
use x509_parser::certificate::X509Certificate;
use x509_parser::der_parser::oid::Oid;
use x509_parser::extensions::GeneralName::URI;
use x509_parser::extensions::ParsedExtension;
use x509_parser::oid_registry;

/// Parse the [`Certificate`] as an X.509 certificate,
/// validate and return the [`SpiffeId`] from certificate URI SAN.
pub(crate) fn validate_leaf_certificate(cert: &Certificate) -> Result<SpiffeId, CertificateError> {
    let x509 = parse_der_encoded_bytes_as_x509_certificate(cert.content())?;
    validate_x509_leaf_certificate(&x509)?;
    find_spiffe_id(&x509)
}

/// Parse the chain of [`Certificate`] as X.509 certificates and validate them
/// as signing certificates.
pub(crate) fn validate_signing_certificates(certs: &[Certificate]) -> Result<(), CertificateError> {
    for cert in certs {
        let ca = parse_der_encoded_bytes_as_x509_certificate(cert.content())?;
        validate_signing_certificate(&ca)?;
    }
    Ok(())
}

fn validate_x509_leaf_certificate(cert: &X509Certificate<'_>) -> Result<(), CertificateError> {
    validate_leaf_certificate_key_usage(cert)?;

    let basic_constraints =
        get_x509_extension(cert, &oid_registry::OID_X509_EXT_BASIC_CONSTRAINTS)?;
    match basic_constraints {
        ParsedExtension::BasicConstraints(b) if b.ca => {
            Err(CertificateError::LeafCertificateHasCaFlag)
        }
        _ => Ok(()),
    }
}

fn validate_signing_certificate(cert: &X509Certificate<'_>) -> Result<(), CertificateError> {
    let basic_constraints =
        get_x509_extension(cert, &oid_registry::OID_X509_EXT_BASIC_CONSTRAINTS)?;
    match basic_constraints {
        ParsedExtension::BasicConstraints(b) if !b.ca => {
            return Err(CertificateError::SigningCertificatedNoCa)
        }
        _ => {}
    };

    let key_usage = get_x509_extension(cert, &oid_registry::OID_X509_EXT_KEY_USAGE)?;
    match key_usage {
        ParsedExtension::KeyUsage(k) if !k.key_cert_sign() => {
            Err(CertificateError::SigningCertificatedNoKeyCertSign)
        }
        _ => Ok(()),
    }
}

fn validate_leaf_certificate_key_usage(cert: &X509Certificate<'_>) -> Result<(), CertificateError> {
    let key_usage = get_x509_extension(cert, &oid_registry::OID_X509_EXT_KEY_USAGE)?;
    match key_usage {
        ParsedExtension::KeyUsage(k) if !k.digital_signature() => {
            Err(CertificateError::LeafCertificatedNoDigitalSignature)
        }

        ParsedExtension::KeyUsage(k) if k.crl_sign() => {
            Err(CertificateError::LeafCertificateHasCrlSign)
        }
        ParsedExtension::KeyUsage(k) if k.key_cert_sign() => {
            Err(CertificateError::LeafCertificateHasKeyCertSign)
        }
        _ => Ok(()),
    }
}

fn find_spiffe_id(cert: &X509Certificate<'_>) -> Result<SpiffeId, CertificateError> {
    let san_ext = get_x509_extension(cert, &oid_registry::OID_X509_EXT_SUBJECT_ALT_NAME)?;

    return match san_ext {
        ParsedExtension::SubjectAlternativeName(s) => {
            let uri_san = s
                .general_names
                .iter()
                .filter_map(|n| match n {
                    URI(n) => Some(*n),
                    _ => None,
                })
                .next();

            let uri_str = match uri_san {
                None => return Err(CertificateError::MissingSpiffeId),
                Some(s) => s,
            };

            Ok(SpiffeId::try_from(uri_str)?)
        }
        _ => unreachable!(),
    };
}

// Returns the X.509 extension in the certificate the for the provided OID.
fn get_x509_extension<'a, 'b>(
    cert: &'a X509Certificate<'_>,
    oid: &'b Oid<'a>,
) -> Result<&'a ParsedExtension<'a>, CertificateError> {
    let extensions = &cert.tbs_certificate.extensions;
    let parsed_extension = match extensions.get(oid) {
        None => {
            return Err(CertificateError::MissingX509Extension(oid.to_string()));
        }
        Some(s) => s.parsed_extension(),
    };
    Ok(parsed_extension)
}
