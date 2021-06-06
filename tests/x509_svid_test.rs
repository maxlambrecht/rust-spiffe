mod x509_svid_tests {
    use std::str::FromStr;

    use rust_spiffe::spiffe_id::SpiffeId;
    use rust_spiffe::svid::x509::{X509Svid, X509SvidError};

    use rust_spiffe::cert::errors::{CertificateError, PrivateKeyError};

    #[test]
    fn test_x509_svid_parse_from_der_chain() {
        let certs_bytes: &[u8] = include_bytes!("testdata/svid/x509/1-svid-chain.der");
        let key_bytes: &[u8] = include_bytes!("testdata/svid/x509/1-key.der");

        let x509_svid = X509Svid::parse_from_der(certs_bytes, key_bytes).unwrap();

        assert_eq!(
            x509_svid.spiffe_id(),
            &SpiffeId::from_str("spiffe://example.org/service").unwrap()
        );

        assert_eq!(x509_svid.cert_chain().len(), 2);
        assert_eq!(x509_svid.private_key().as_ref(), key_bytes);
    }

    #[test]
    fn test_x509_svid_parse_from_single_der() {
        // the cert has a DNS, besides the URI SAN.
        let cert_bytes: &[u8] = include_bytes!("testdata/svid/x509/svid-with-dns.der");
        let key_bytes: &[u8] = include_bytes!("testdata/svid/x509/svid-with-dns-key.der");

        let x509_svid = X509Svid::parse_from_der(cert_bytes, key_bytes).unwrap();

        assert_eq!(
            x509_svid.spiffe_id(),
            &SpiffeId::from_str("spiffe://example.org/service").unwrap()
        );

        assert_eq!(x509_svid.cert_chain().len(), 1);
        assert_eq!(x509_svid.leaf().as_ref(), cert_bytes);
        assert_eq!(x509_svid.private_key().as_ref(), key_bytes);
    }

    #[test]
    fn test_x509_svid_parse_from_der_corrupted_cert() {
        let certs_bytes: &[u8] = include_bytes!("testdata/svid/x509/corrupted");
        let key_bytes: &[u8] = include_bytes!("testdata/svid/x509/1-key.der");

        let result = X509Svid::parse_from_der(certs_bytes, key_bytes);

        assert!(matches!(
            result.unwrap_err(),
            X509SvidError::Certificate(CertificateError::ChainDecode(..))
        ));
    }

    #[test]
    fn test_x509_svid_parse_from_der_corrupted_private_key() {
        let certs_bytes: &[u8] = include_bytes!("testdata/svid/x509/1-svid-chain.der");
        let key_bytes: &[u8] = include_bytes!("testdata/svid/x509/corrupted");

        let result = X509Svid::parse_from_der(certs_bytes, key_bytes);

        assert!(matches!(
            result.unwrap_err(),
            X509SvidError::PrivateKey(PrivateKeyError::DecodePkcs8(..))
        ));
    }

    #[test]
    fn test_x509_svid_parse_from_der_leaf_ca() {
        let certs_bytes = include_bytes!("testdata/svid/x509/wrong-leaf-ca-true.der");
        let key_bytes = include_bytes!("testdata/svid/x509/1-key.der");

        let result = X509Svid::parse_from_der(certs_bytes, key_bytes);

        assert_eq!(result.unwrap_err(), X509SvidError::LeafCertificateHasCaFlag);
    }

    #[test]
    fn test_x509_svid_parse_from_der_crl_sign() {
        let certs_bytes = include_bytes!("testdata/svid/x509/wrong-leaf-crl-sign.der");
        let key_bytes = include_bytes!("testdata/svid/x509/1-key.der");

        let result = X509Svid::parse_from_der(certs_bytes, key_bytes);

        assert_eq!(
            result.unwrap_err(),
            X509SvidError::LeafCertificateHasCrlSign
        );
    }

    #[test]
    fn test_x509_svid_parse_from_der_key_cert_sign() {
        let certs_bytes = include_bytes!("testdata/svid/x509/wrong-leaf-cert-sign.der");
        let key_bytes = include_bytes!("testdata/svid/x509/1-key.der");

        let result = X509Svid::parse_from_der(certs_bytes, key_bytes);

        assert_eq!(
            result.unwrap_err(),
            X509SvidError::LeafCertificateHasKeyCertSign
        );
    }

    #[test]
    fn test_x509_svid_parse_from_der_no_digital_signature() {
        let certs_bytes = include_bytes!("testdata/svid/x509/wrong-leaf-no-digital-signature.der");
        let key_bytes = include_bytes!("testdata/svid/x509/1-key.der");

        let result = X509Svid::parse_from_der(certs_bytes, key_bytes);

        assert_eq!(
            result.unwrap_err(),
            X509SvidError::LeafCertificatedNoDigitalSignature
        );
    }

    #[test]
    fn test_x509_svid_parse_from_der_no_spiffe_id() {
        let certs_bytes = include_bytes!("testdata/svid/x509/wrong-leaf-empty-id.der");
        let key_bytes = include_bytes!("testdata/svid/x509/1-key.der");

        let result = X509Svid::parse_from_der(certs_bytes, key_bytes);

        assert_eq!(result.unwrap_err(), X509SvidError::MissingSpiffeId);
    }

    #[test]
    fn test_x509_svid_parse_from_der_intermediate_no_ca() {
        let certs_bytes = include_bytes!("testdata/svid/x509/wrong-intermediate-no-ca.der");
        let key_bytes = include_bytes!("testdata/svid/x509/1-key.der");

        let result = X509Svid::parse_from_der(certs_bytes, key_bytes);

        assert_eq!(result.unwrap_err(), X509SvidError::SigningCertificatedNoCa);
    }

    #[test]
    fn test_x509_svid_parse_from_der_intermediate_no_key_cert_sign() {
        let certs_bytes =
            include_bytes!("testdata/svid/x509/wrong-intermediate-no-key-cert-sign.der");
        let key_bytes = include_bytes!("testdata/svid/x509/1-key.der");

        let result = X509Svid::parse_from_der(certs_bytes, key_bytes);

        assert_eq!(
            result.unwrap_err(),
            X509SvidError::SigningCertificatedNoKeyCertSign
        );
    }

    #[test]
    fn test_x509_svid_is_parseable_as_openssl_x509() {
        let certs_bytes: &[u8] = include_bytes!("testdata/svid/x509/1-svid-chain.der");
        let key_bytes: &[u8] = include_bytes!("testdata/svid/x509/1-key.der");

        let x509_svid = X509Svid::parse_from_der(certs_bytes, key_bytes).unwrap();

        for cert in x509_svid.cert_chain() {
            openssl::x509::X509::from_der(cert.as_ref()).unwrap();
        }
        openssl::pkey::PKey::private_key_from_der(x509_svid.private_key().as_ref()).unwrap();
    }
}
