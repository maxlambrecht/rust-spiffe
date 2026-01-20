#[cfg(feature = "x509")]
mod x509_svid_tests {
    use std::str::FromStr;

    use spiffe::{SpiffeId, X509Svid, X509SvidError};

    use spiffe::cert::error::{CertificateError, PrivateKeyError};

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
            X509SvidError::Certificate(CertificateError::ParseX509Certificate(..))
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
            X509SvidError::LeafCertificateMissingDigitalSignature
        );
    }

    #[test]
    fn test_x509_svid_parse_from_der_no_spiffe_id() {
        let certs_bytes = include_bytes!("testdata/svid/x509/wrong-leaf-empty-id.der");
        let key_bytes = include_bytes!("testdata/svid/x509/1-key.der");

        let result = X509Svid::parse_from_der(certs_bytes, key_bytes);

        assert_eq!(
            result.unwrap_err(),
            X509SvidError::Certificate(CertificateError::MissingSpiffeId)
        );
    }

    #[test]
    fn test_x509_svid_parse_from_der_intermediate_no_ca() {
        let certs_bytes = include_bytes!("testdata/svid/x509/wrong-intermediate-no-ca.der");
        let key_bytes = include_bytes!("testdata/svid/x509/1-key.der");

        let result = X509Svid::parse_from_der(certs_bytes, key_bytes);

        assert_eq!(
            result.unwrap_err(),
            X509SvidError::SigningCertificateMissingCaFlag
        );
    }

    #[test]
    fn test_x509_svid_parse_from_der_intermediate_no_key_cert_sign() {
        let certs_bytes =
            include_bytes!("testdata/svid/x509/wrong-intermediate-no-key-cert-sign.der");
        let key_bytes = include_bytes!("testdata/svid/x509/1-key.der");

        let result = X509Svid::parse_from_der(certs_bytes, key_bytes);

        assert_eq!(
            result.unwrap_err(),
            X509SvidError::SigningCertificateMissingKeyCertSign
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

    /// Regression test for issue #147: X.509-SVID with an empty Subject Name (0-element RDNSequence).
    ///
    /// Historically, certificates whose Subject is present but empty triggered ASN.1 decoding
    /// failures in some parsing paths, resulting in errors such as:
    /// `InvalidX509Svid(Certificate(ChainDecode(EmptyBuffer)))`.
    ///
    /// This test ensures that `X509Svid::parse_from_der` continues to accept such certificates
    /// and that the SPIFFE ID and associated key material remain usable.
    #[test]
    fn test_x509_svid_with_empty_subject_name_sequence() {
        let cert_bytes: &[u8] = include_bytes!("testdata/svid/x509/empty-subject-name.der");
        let key_bytes: &[u8] = include_bytes!("testdata/svid/x509/empty-subject-name-key.der");

        let x509_svid = X509Svid::parse_from_der(cert_bytes, key_bytes)
            .expect("issue #147 regression: X509Svid::parse_from_der should succeed");

        assert_eq!(
            x509_svid.cert_chain().len(),
            1,
            "unexpected cert chain length"
        );
        assert_eq!(x509_svid.leaf().as_ref(), cert_bytes, "leaf cert mismatch");

        assert_eq!(
            x509_svid.private_key().as_ref(),
            key_bytes,
            "private key mismatch"
        );

        // SPIFFE ID extraction must work.
        let expected = SpiffeId::from_str("spiffe://example.org/test-empty-subject")
            .expect("test SPIFFE ID must be valid");
        assert_eq!(x509_svid.spiffe_id(), &expected, "SPIFFE ID mismatch");

        // Interop sanity checks
        for cert in x509_svid.cert_chain() {
            openssl::x509::X509::from_der(cert.as_ref())
                .expect("OpenSSL should parse certificate DER");
        }
        openssl::pkey::PKey::private_key_from_der(x509_svid.private_key().as_ref())
            .expect("OpenSSL should parse private key DER");
    }
    /// Security test: Certificate chain length must be bounded to prevent DoS attacks.
    ///
    /// This test verifies that `X509Svid::parse_from_der` rejects certificate chains
    /// exceeding `MAX_CERT_CHAIN_LENGTH` (16 certificates), preventing resource exhaustion.
    #[test]
    fn test_certificate_chain_length_limit() {
        use spiffe::cert::error::CertificateError;

        // Build a chain exceeding MAX_CERT_CHAIN_LENGTH by concatenating the test certificate chain.
        let cert_chain: &[u8] = include_bytes!("testdata/svid/x509/1-svid-chain.der");
        let key_bytes: &[u8] = include_bytes!("testdata/svid/x509/1-key.der");

        let mut oversized_chain = Vec::new();
        for _ in 0..9 {
            oversized_chain.extend_from_slice(cert_chain);
        }

        let result = X509Svid::parse_from_der(&oversized_chain, key_bytes);
        assert!(
            matches!(
                result,
                Err(X509SvidError::Certificate(
                    CertificateError::TooManyCertificates { max: 16 }
                ))
            ),
            "should reject certificate chain exceeding MAX_CERT_CHAIN_LENGTH"
        );
    }
}
