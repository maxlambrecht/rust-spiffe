use rust_spiffe::bundle::x509::{X509Bundle, X509BundleError};
use rust_spiffe::cert::errors::CertificateError;
use rust_spiffe::spiffe_id::TrustDomain;

#[test]
fn test_x509_bundle_parse_from_der() {
    let bundle_bytes = include_bytes!("testdata/bundle/x509/bundle.der");

    let trust_domain = TrustDomain::new("domain.test").unwrap();
    let x509_bundle = X509Bundle::parse_from_der(trust_domain.to_owned(), bundle_bytes).unwrap();

    assert_eq!(x509_bundle.trust_domain(), &trust_domain);
    assert_eq!(x509_bundle.authorities().len(), 2);
}

#[test]
fn test_x509_bundle_parse_from_authorities() {
    let authority1: &[u8] = include_bytes!("testdata/bundle/x509/cert1.der");
    let authority2: &[u8] = include_bytes!("testdata/bundle/x509/cert2.der");

    let x509_authorities = &[authority1, authority2];

    let trust_domain = TrustDomain::new("domain.test").unwrap();
    let x509_bundle =
        X509Bundle::from_x509_authorities(trust_domain.to_owned(), x509_authorities).unwrap();

    assert_eq!(x509_bundle.trust_domain(), &trust_domain);
    assert_eq!(x509_bundle.authorities().len(), 2);
}

#[test]
fn test_x509_bundle_parse_from_der_corrupted() {
    let bundle_bytes = include_bytes!("testdata/bundle/x509/corrupted");

    let trust_domain = TrustDomain::new("example.org").unwrap();
    let result = X509Bundle::parse_from_der(trust_domain, bundle_bytes);

    assert!(matches!(
        result.unwrap_err(),
        X509BundleError::Certificate(CertificateError::ChainDecode(..))
    ));
}

#[test]
fn test_x509_bundle_from_x509_authorities_corrupted() {
    let bundle_bytes: &[u8] = include_bytes!("testdata/bundle/x509/corrupted");

    let trust_domain = TrustDomain::new("example.org").unwrap();
    let result = X509Bundle::from_x509_authorities(trust_domain, &[bundle_bytes]);

    assert!(matches!(
        result.unwrap_err(),
        X509BundleError::Certificate(CertificateError::ParseX509Certificate(..))
    ));
}

#[test]
fn test_x509_bundle_authorities_parseable_as_openssl_x509_certs() {
    let bundle_bytes = include_bytes!("testdata/bundle/x509/bundle.der");

    let trust_domain = TrustDomain::new("example.org").unwrap();
    let x509_bundle = X509Bundle::parse_from_der(trust_domain, bundle_bytes).unwrap();

    for cert in x509_bundle.authorities() {
        openssl::x509::X509::from_der(cert.as_ref()).unwrap();
    }
}
