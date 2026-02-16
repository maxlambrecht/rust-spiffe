#![expect(missing_docs, reason = "integration test")]
#![expect(unused_crate_dependencies, reason = "used in the library target")]

#[cfg(feature = "x509")]
#[expect(
    clippy::tests_outside_test_module,
    reason = "https://github.com/rust-lang/rust-clippy/issues/11024"
)]
mod x509_svid_tests {
    use std::str::FromStr as _;

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

    /// Regression test for issue #147: X.509-SVID with an empty Subject Name (0-element `RDNSequence`).
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
    /// Security test: Certificate chain length must be bounded to prevent `DoS` attacks.
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

    // --- Helpers for extension corruption tests ---

    /// DER-encoded OID for `BasicConstraints` (2.5.29.19).
    const OID_BASIC_CONSTRAINTS_DER: &[u8] = b"\x06\x03\x55\x1d\x13";
    /// DER-encoded OID for `KeyUsage` (2.5.29.15).
    const OID_KEY_USAGE_DER: &[u8] = b"\x06\x03\x55\x1d\x0f";

    /// Corrupts the content of an X.509 extension identified by its DER-encoded OID.
    ///
    /// Finds the first occurrence of `oid_der` in `der`, then replaces the associated
    /// OCTET STRING content with invalid bytes. This produces a certificate where the
    /// extension OID is present but the value cannot be parsed.
    #[expect(
        clippy::indexing_slicing,
        clippy::expect_used,
        reason = "test helper operating on known-valid test data with assertions"
    )]
    fn corrupt_extension_value(der: &[u8], oid_der: &[u8]) -> Vec<u8> {
        let mut result = der.to_vec();
        let oid_pos = der
            .windows(oid_der.len())
            .position(|w| w == oid_der)
            .expect("OID not found in DER bytes");

        let mut pos = oid_pos + oid_der.len();

        // Skip optional BOOLEAN (critical flag): tag=0x01, length=0x01, value
        if pos < der.len() && der[pos] == 0x01 {
            pos += 3;
        }

        // Expect OCTET STRING tag (0x04)
        assert_eq!(
            der[pos], 0x04,
            "expected OCTET STRING tag after extension OID"
        );
        pos += 1;

        // Read single-byte length (sufficient for test extension values)
        let content_len = der[pos] as usize;
        pos += 1;

        // Replace content with invalid bytes
        for byte in &mut result[pos..pos + content_len] {
            *byte = 0xFF;
        }

        result
    }

    /// Splits a concatenated DER certificate chain into individual certificates
    /// by parsing the outer SEQUENCE tag and length of each certificate.
    #[expect(
        clippy::indexing_slicing,
        clippy::missing_asserts_for_indexing,
        reason = "test helper operating on known-valid DER data with assertions"
    )]
    fn split_der_chain(chain: &[u8]) -> Vec<Vec<u8>> {
        let mut certs = Vec::new();
        let mut rest = chain;
        while !rest.is_empty() {
            assert_eq!(rest[0], 0x30, "expected SEQUENCE tag");
            let (body_len, header_len) = if rest[1] & 0x80 == 0 {
                (rest[1] as usize, 2)
            } else {
                let num_len_bytes = (rest[1] & 0x7F) as usize;
                let mut len = 0usize;
                for i in 0..num_len_bytes {
                    len = (len << 8) | rest[2 + i] as usize;
                }
                (len, 2 + num_len_bytes)
            };
            let total = header_len + body_len;
            certs.push(rest[..total].to_vec());
            rest = &rest[total..];
        }
        certs
    }

    // --- Unparseable extension tests ---
    //
    // These tests verify that certificates with malformed (present but unparseable)
    // BasicConstraints or KeyUsage extensions are rejected with the dedicated
    // `UnparseableExtension` error, preventing validation bypass via malformed
    // extensions.

    #[test]
    fn test_leaf_unparseable_basic_constraints() {
        let cert_bytes: &[u8] = include_bytes!("testdata/svid/x509/svid-with-dns.der");
        let key_bytes: &[u8] = include_bytes!("testdata/svid/x509/svid-with-dns-key.der");

        let corrupted = corrupt_extension_value(cert_bytes, OID_BASIC_CONSTRAINTS_DER);
        let result = X509Svid::parse_from_der(&corrupted, key_bytes);

        assert_eq!(
            result.unwrap_err(),
            X509SvidError::UnparseableExtension {
                extension: "BasicConstraints"
            }
        );
    }

    #[test]
    fn test_leaf_unparseable_key_usage() {
        let cert_bytes: &[u8] = include_bytes!("testdata/svid/x509/svid-with-dns.der");
        let key_bytes: &[u8] = include_bytes!("testdata/svid/x509/svid-with-dns-key.der");

        let corrupted = corrupt_extension_value(cert_bytes, OID_KEY_USAGE_DER);
        let result = X509Svid::parse_from_der(&corrupted, key_bytes);

        assert_eq!(
            result.unwrap_err(),
            X509SvidError::UnparseableExtension {
                extension: "KeyUsage"
            }
        );
    }

    #[test]
    fn test_signing_cert_unparseable_basic_constraints() {
        let chain_bytes: &[u8] = include_bytes!("testdata/svid/x509/1-svid-chain.der");
        let key_bytes: &[u8] = include_bytes!("testdata/svid/x509/1-key.der");

        let mut certs = split_der_chain(chain_bytes).into_iter();
        let leaf = certs.next().unwrap();
        let signing = certs.next().unwrap();

        // Corrupt BasicConstraints in the signing certificate only
        let corrupted_signing = corrupt_extension_value(&signing, OID_BASIC_CONSTRAINTS_DER);
        let mut corrupted_chain = leaf;
        corrupted_chain.extend_from_slice(&corrupted_signing);

        let result = X509Svid::parse_from_der(&corrupted_chain, key_bytes);

        assert_eq!(
            result.unwrap_err(),
            X509SvidError::UnparseableExtension {
                extension: "BasicConstraints"
            }
        );
    }

    #[test]
    fn test_signing_cert_unparseable_key_usage() {
        let chain_bytes: &[u8] = include_bytes!("testdata/svid/x509/1-svid-chain.der");
        let key_bytes: &[u8] = include_bytes!("testdata/svid/x509/1-key.der");

        let mut certs = split_der_chain(chain_bytes).into_iter();
        let leaf = certs.next().unwrap();
        let signing = certs.next().unwrap();

        // Corrupt KeyUsage in the signing certificate only
        let corrupted_signing = corrupt_extension_value(&signing, OID_KEY_USAGE_DER);
        let mut corrupted_chain = leaf;
        corrupted_chain.extend_from_slice(&corrupted_signing);

        let result = X509Svid::parse_from_der(&corrupted_chain, key_bytes);

        assert_eq!(
            result.unwrap_err(),
            X509SvidError::UnparseableExtension {
                extension: "KeyUsage"
            }
        );
    }
}
