use crate::cert::error::CertificateError;
use crate::cert::parsing::{get_x509_extension, parse_der_encoded_bytes_as_x509_certificate};
use crate::cert::Certificate;
use crate::spiffe_id::SpiffeId;
use crate::svid::x509::X509SvidError;
use x509_parser::certificate::X509Certificate;
use x509_parser::extensions::GeneralName;
use x509_parser::extensions::ParsedExtension;
use x509_parser::oid_registry;

/// Parses `cert` as X.509, validates it as an X.509-SVID leaf,
/// and returns the [`SpiffeId`] from the URI SAN.
pub(crate) fn validate_leaf_certificate(cert: &Certificate) -> Result<SpiffeId, X509SvidError> {
    let x509 = parse_der_encoded_bytes_as_x509_certificate(cert.as_bytes())?;
    validate_x509_leaf_certificate(&x509)?;
    find_spiffe_id(&x509)
}

/// Parses and validates `certs` as signing certificates.
pub(crate) fn validate_signing_certificates(certs: &[Certificate]) -> Result<(), X509SvidError> {
    for cert in certs {
        let x509 = parse_der_encoded_bytes_as_x509_certificate(cert.as_bytes())?;
        validate_signing_certificate(&x509)?;
    }
    Ok(())
}

fn validate_x509_leaf_certificate(cert: &X509Certificate<'_>) -> Result<(), X509SvidError> {
    validate_leaf_certificate_key_usage(cert)?;

    let basic_constraints =
        get_x509_extension(cert, &oid_registry::OID_X509_EXT_BASIC_CONSTRAINTS)?;
    match basic_constraints {
        ParsedExtension::BasicConstraints(b) if b.ca => {
            Err(X509SvidError::LeafCertificateHasCaFlag)
        }
        _ => Ok(()),
    }
}

fn validate_signing_certificate(cert: &X509Certificate<'_>) -> Result<(), X509SvidError> {
    let basic_constraints =
        get_x509_extension(cert, &oid_registry::OID_X509_EXT_BASIC_CONSTRAINTS)?;
    if matches!(basic_constraints, ParsedExtension::BasicConstraints(b) if !b.ca) {
        return Err(X509SvidError::SigningCertificateMissingCaFlag);
    }

    let key_usage = get_x509_extension(cert, &oid_registry::OID_X509_EXT_KEY_USAGE)?;
    match key_usage {
        ParsedExtension::KeyUsage(k) if !k.key_cert_sign() => {
            Err(X509SvidError::SigningCertificateMissingKeyCertSign)
        }
        _ => Ok(()),
    }
}

fn validate_leaf_certificate_key_usage(cert: &X509Certificate<'_>) -> Result<(), X509SvidError> {
    let key_usage = get_x509_extension(cert, &oid_registry::OID_X509_EXT_KEY_USAGE)?;
    match key_usage {
        ParsedExtension::KeyUsage(k) if !k.digital_signature() => {
            Err(X509SvidError::LeafCertificateMissingDigitalSignature)
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
    let san_ext = get_x509_extension(cert, &oid_registry::OID_X509_EXT_SUBJECT_ALT_NAME)?;

    let uris: Vec<&str> = match san_ext {
        ParsedExtension::SubjectAlternativeName(s) => s
            .general_names
            .iter()
            .filter_map(|n| match n {
                GeneralName::URI(u) => Some(*u),
                _ => None,
            })
            .collect(),
        other => {
            return Err(X509SvidError::Certificate(
                CertificateError::UnexpectedExtension(format!("{other:?}")),
            ));
        }
    };

    if uris.is_empty() {
        return Err(X509SvidError::MissingSpiffeId);
    }

    // Prefer the first URI SAN that parses as a SPIFFE ID.
    let mut last_err = None;
    for uri in uris {
        match SpiffeId::try_from(uri) {
            Ok(id) => return Ok(id),
            Err(e) => last_err = Some(e),
        }
    }

    Err(last_err
        .unwrap_or_else(|| unreachable!("guaranteed non-empty here"))
        .into())
}
