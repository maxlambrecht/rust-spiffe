use crate::cert::Certificate;
use crate::cert::errors::CertificateError;
use crate::cert::parsing::{get_x509_extension, parse_der_encoded_bytes_as_x509_certificate};
use crate::spiffe_id::SpiffeId;
use crate::svid::x509::X509SvidError;
use std::convert::TryFrom;
use x509_parser::certificate::X509Certificate;
use x509_parser::extensions::GeneralName::URI;
use x509_parser::extensions::ParsedExtension;
use x509_parser::oid_registry;

/// Parse the [`Certificate`] as an X.509 certificate,
/// validate and return the [`SpiffeId`] from certificate URI SAN.
pub(crate) fn validate_leaf_certificate(cert: &Certificate) -> Result<SpiffeId, X509SvidError> {
    let x509 = parse_der_encoded_bytes_as_x509_certificate(cert.content())?;
    validate_x509_leaf_certificate(&x509)?;
    find_spiffe_id(&x509)
}

/// Parse the chain of [`Certificate`] as X.509 certificates and validate them
/// as signing certificates.
pub(crate) fn validate_signing_certificates(certs: &[Certificate]) -> Result<(), X509SvidError> {
    for cert in certs {
        let ca = parse_der_encoded_bytes_as_x509_certificate(cert.content())?;
        validate_signing_certificate(&ca)?;
    }
    Ok(())
}

fn validate_x509_leaf_certificate(cert: &X509Certificate<'_>) -> Result<(), X509SvidError> {
    validate_leaf_certificate_key_usage(cert)?;

    let basic_constraints = get_x509_extension(cert, oid_registry::OID_X509_EXT_BASIC_CONSTRAINTS)?;
    match basic_constraints {
        ParsedExtension::BasicConstraints(b) if b.ca => {
            Err(X509SvidError::LeafCertificateHasCaFlag)
        }
        _ => Ok(()),
    }
}

fn validate_signing_certificate(cert: &X509Certificate<'_>) -> Result<(), X509SvidError> {
    let basic_constraints = get_x509_extension(cert, oid_registry::OID_X509_EXT_BASIC_CONSTRAINTS)?;
    match basic_constraints {
        ParsedExtension::BasicConstraints(b) if !b.ca => {
            return Err(X509SvidError::SigningCertificatedNoCa);
        }
        _ => {}
    };

    let key_usage = get_x509_extension(cert, oid_registry::OID_X509_EXT_KEY_USAGE)?;
    match key_usage {
        ParsedExtension::KeyUsage(k) if !k.key_cert_sign() => {
            Err(X509SvidError::SigningCertificatedNoKeyCertSign)
        }
        _ => Ok(()),
    }
}

fn validate_leaf_certificate_key_usage(cert: &X509Certificate<'_>) -> Result<(), X509SvidError> {
    let key_usage = get_x509_extension(cert, oid_registry::OID_X509_EXT_KEY_USAGE)?;
    match key_usage {
        ParsedExtension::KeyUsage(k) if !k.digital_signature() => {
            Err(X509SvidError::LeafCertificatedNoDigitalSignature)
        }

        ParsedExtension::KeyUsage(k) if k.crl_sign() => {
            Err(X509SvidError::LeafCertificateHasCrlSign)
        }
        ParsedExtension::KeyUsage(k) if k.key_cert_sign() => {
            Err(X509SvidError::LeafCertificateHasKeyCertSign)
        }
        _ => Ok(()),
    }
}

fn find_spiffe_id(cert: &X509Certificate<'_>) -> Result<SpiffeId, X509SvidError> {
    let san_ext = get_x509_extension(cert, oid_registry::OID_X509_EXT_SUBJECT_ALT_NAME)?;

    match san_ext {
        ParsedExtension::SubjectAlternativeName(s) => {
            let uri_san = s
                .general_names
                .iter()
                .find(|n| matches!(n, URI(_)))
                .and_then(|n| match n {
                    URI(n) => Some(*n),
                    _ => None,
                });

            let uri_str = match uri_san {
                None => return Err(X509SvidError::MissingSpiffeId),
                Some(s) => s,
            };

            Ok(SpiffeId::try_from(uri_str)?)
        }
        other => Err(X509SvidError::Certificate(
            CertificateError::UnexpectedExtension(format!("{other:?}")),
        )),
    }
}
