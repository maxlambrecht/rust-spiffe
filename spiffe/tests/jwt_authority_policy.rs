//! Signed public-API regressions for trusted JWK policy and RSA strength.

#![expect(
    unused_crate_dependencies,
    reason = "used in other test and library targets"
)]

#[cfg(test)]
#[cfg(feature = "jwt")]
#[cfg_attr(
    any(feature = "jwt-verify-rust-crypto", feature = "jwt-verify-aws-lc-rs"),
    expect(
        clippy::indexing_slicing,
        reason = "reviewed fixture fields and bounded byte arrays; failures should panic"
    )
)]
mod tests {
    use serde::Deserialize;
    use serde_json::{json, Value};
    use spiffe::bundle::jwt::JwtAuthority;
    use spiffe::{JwtBundle, JwtBundleSet, JwtSvid, TrustDomain};

    #[derive(Deserialize)]
    struct Fixture {
        name: String,
        #[cfg(any(feature = "jwt-verify-rust-crypto", feature = "jwt-verify-aws-lc-rs"))]
        alg: String,
        #[cfg(any(feature = "jwt-verify-rust-crypto", feature = "jwt-verify-aws-lc-rs"))]
        bits: usize,
        #[cfg(any(feature = "jwt-verify-rust-crypto", feature = "jwt-verify-aws-lc-rs"))]
        jwk: Value,
        token: String,
    }

    fn fixtures() -> Vec<Fixture> {
        serde_json::from_str(include_str!("testdata/jwt/authority-policy.json")).unwrap()
    }

    fn bundles(jwk: &Value) -> JwtBundleSet {
        let mut bundle = JwtBundle::new(TrustDomain::new("example.org").unwrap());
        bundle
            .add_jwk_authority_json(&serde_json::to_vec(jwk).unwrap())
            .unwrap();
        std::iter::once(bundle).collect()
    }

    #[test]
    fn parse_only_storage_preserves_unvalidated_authorities() {
        let row = fixtures().remove(0);
        assert_eq!(row.name, "ec_ES256");
        for jwk in [
            json!({"kid":"probe", "kty":"RSA", "alg":null, "n":"", "e":""}),
            json!({"kid":"probe", "use":"enc", "key_ops":["sign"], "extension":{"x":true}}),
        ] {
            let authority =
                JwtAuthority::from_jwk_json(&serde_json::to_vec(&jwk).unwrap()).unwrap();
            assert_eq!(
                serde_json::from_slice::<Value>(authority.jwk_json()).unwrap(),
                jwk
            );
            assert!(bundles(&jwk)
                .get(&TrustDomain::new("example.org").unwrap())
                .unwrap()
                .find_jwt_authority("probe")
                .is_some());
        }
        JwtSvid::parse_insecure(&row.token).unwrap();
    }

    #[cfg(any(feature = "jwt-verify-rust-crypto", feature = "jwt-verify-aws-lc-rs"))]
    mod verification {
        use super::*;
        use base64ct::{Base64UrlUnpadded, Encoding as _};
        use spiffe::JwtSvidError;

        fn verify(row: &Fixture, jwk: &Value) -> Result<JwtSvid, JwtSvidError> {
            JwtSvid::parse_and_validate(&row.token, &bundles(jwk), &["receiver"])
        }

        fn control() -> Fixture {
            fixtures()
                .into_iter()
                .find(|r| r.name == "ec_ES256")
                .unwrap()
        }

        #[test]
        fn authority_errors_distinguish_policy_from_signature_failure() {
            let row = control();
            verify(&row, &row.jwk).unwrap();
            let mut jwk = row.jwk.clone();
            jwk["alg"] = json!("ES384");
            assert!(matches!(
                verify(&row, &jwk),
                Err(JwtSvidError::AuthorityAlgorithmMismatch { .. })
            ));
            jwk["alg"] = Value::Null;
            assert!(matches!(
                verify(&row, &jwk),
                Err(JwtSvidError::InvalidAuthorityMetadata("alg"))
            ));
            jwk = row.jwk.clone();
            jwk["use"] = json!("enc");
            assert!(matches!(
                verify(&row, &jwk),
                Err(JwtSvidError::UnsupportedAuthorityPurpose)
            ));
            jwk = row.jwk.clone();
            jwk["key_ops"] = json!(["sign"]);
            assert!(matches!(
                verify(&row, &jwk),
                Err(JwtSvidError::AuthorityVerificationNotPermitted)
            ));
            jwk = row.jwk.clone();
            jwk["crv"] = json!("P-384");
            assert!(matches!(
                verify(&row, &jwk),
                Err(JwtSvidError::AuthorityCurveMismatch(_))
            ));
            let rows = fixtures();
            let rsa = rows.iter().find(|r| r.name == "rsa_2047_RS256").unwrap();
            assert!(matches!(
                verify(rsa, &rsa.jwk),
                Err(JwtSvidError::WeakRsaAuthority(2047))
            ));
            let rsa = rows.iter().find(|r| r.name == "rsa_2048_RS256").unwrap();
            let n = Base64UrlUnpadded::decode_vec(rsa.jwk["n"].as_str().unwrap()).unwrap();
            jwk = rsa.jwk.clone();
            jwk["n"] = json!(Base64UrlUnpadded::encode_string(&[vec![0], n].concat()));
            assert!(matches!(
                verify(rsa, &jwk),
                Err(JwtSvidError::NonCanonicalRsaComponent("n"))
            ));
            jwk["n"] = json!("!");
            assert!(matches!(
                verify(rsa, &jwk),
                Err(JwtSvidError::InvalidAuthorityKeyComponent("n"))
            ));
            let wrong = rows
                .iter()
                .find(|r| r.name == "control_wrong_signature")
                .unwrap();
            assert!(
                matches!(verify(wrong, &wrong.jwk), Err(JwtSvidError::InvalidToken(error))
                if error.kind() == spiffe::JwtVerificationErrorKind::InvalidSignature)
            );
        }

        #[test]
        fn signed_fixtures_verify_independently_with_openssl() {
            use openssl::bn::{BigNum, BigNumContext};
            use openssl::ec::{EcGroup, EcKey};
            use openssl::ecdsa::EcdsaSig;
            use openssl::hash::MessageDigest;
            use openssl::nid::Nid;
            use openssl::pkey::PKey;
            use openssl::rsa::{Padding, Rsa};
            use openssl::sign::{RsaPssSaltlen, Verifier};

            for row in fixtures() {
                let (input, encoded_signature) = row.token.rsplit_once('.').unwrap();
                let mut signature = Base64UrlUnpadded::decode_vec(encoded_signature).unwrap();
                let key = if row.bits == 0 {
                    let width = if row.alg == "ES256" { 32 } else { 48 };
                    let group = EcGroup::from_curve_name(if width == 32 {
                        Nid::X9_62_PRIME256V1
                    } else {
                        Nid::SECP384R1
                    })
                    .unwrap();
                    let x = BigNum::from_slice(
                        &Base64UrlUnpadded::decode_vec(row.jwk["x"].as_str().unwrap()).unwrap(),
                    )
                    .unwrap();
                    let y = BigNum::from_slice(
                        &Base64UrlUnpadded::decode_vec(row.jwk["y"].as_str().unwrap()).unwrap(),
                    )
                    .unwrap();
                    let ec = EcKey::from_public_key_affine_coordinates(&group, &x, &y).unwrap();
                    let mut context = BigNumContext::new().unwrap();
                    assert!(ec.public_key().is_on_curve(&group, &mut context).unwrap());
                    let (r, s) = signature.split_at(width);
                    signature = EcdsaSig::from_private_components(
                        BigNum::from_slice(r).unwrap(),
                        BigNum::from_slice(s).unwrap(),
                    )
                    .unwrap()
                    .to_der()
                    .unwrap();
                    PKey::from_ec_key(ec).unwrap()
                } else {
                    let n = BigNum::from_slice(
                        &Base64UrlUnpadded::decode_vec(row.jwk["n"].as_str().unwrap()).unwrap(),
                    )
                    .unwrap();
                    let e = BigNum::from_slice(
                        &Base64UrlUnpadded::decode_vec(row.jwk["e"].as_str().unwrap()).unwrap(),
                    )
                    .unwrap();
                    PKey::from_rsa(Rsa::from_public_components(n, e).unwrap()).unwrap()
                };
                let digest = match row.alg.as_str() {
                    "ES256" | "RS256" | "PS256" => MessageDigest::sha256(),
                    "ES384" | "RS384" | "PS384" => MessageDigest::sha384(),
                    "RS512" | "PS512" => MessageDigest::sha512(),
                    _ => panic!("unsupported fixture algorithm"),
                };
                let mut verifier = Verifier::new(digest, &key).unwrap();
                if row.alg.starts_with("PS") {
                    verifier.set_rsa_padding(Padding::PKCS1_PSS).unwrap();
                    verifier.set_rsa_mgf1_md(digest).unwrap();
                    verifier
                        .set_rsa_pss_saltlen(RsaPssSaltlen::DIGEST_LENGTH)
                        .unwrap();
                }
                verifier.update(input.as_bytes()).unwrap();
                assert_eq!(
                    verifier.verify(&signature).unwrap(),
                    row.name != "control_wrong_signature",
                    "{}",
                    row.name
                );
            }
        }

        #[test]
        fn matching_metadata_and_optional_omissions() {
            for row in fixtures()
                .into_iter()
                .filter(|r| r.name.starts_with("ec_") || r.bits == 2048)
            {
                assert!(
                    verify(&row, &row.jwk).is_ok(),
                    "{} omitted metadata",
                    row.name
                );
                let mut jwk = row.jwk.clone();
                jwk["alg"] = json!(row.alg);
                jwk["extension"] = json!({"nested":true});
                for purpose in [None, Some("sig"), Some("jwt-svid")] {
                    jwk.as_object_mut().unwrap().remove("use");
                    if let Some(purpose) = purpose {
                        jwk["use"] = json!(purpose);
                    }
                    for operations in [
                        None,
                        Some(json!(["verify"])),
                        Some(json!(["sign", "verify"])),
                        Some(json!(["verify", "private-operation"])),
                    ] {
                        jwk.as_object_mut().unwrap().remove("key_ops");
                        if let Some(operations) = operations {
                            jwk["key_ops"] = operations;
                        }
                        assert!(verify(&row, &jwk).is_ok(), "{}: {jwk}", row.name);
                    }
                }
            }
        }

        #[test]
        fn explicit_algorithm_restrictions() {
            for row in fixtures()
                .into_iter()
                .filter(|r| r.name.starts_with("ec_") || r.bits == 2048)
            {
                verify(&row, &row.jwk).unwrap();
                for alg in [
                    json!(if row.alg == "RS256" { "RS384" } else { "RS256" }),
                    json!(if row.alg == "ES256" { "ES384" } else { "ES256" }),
                    json!("unknown"),
                    json!("ES512"),
                    Value::Null,
                    json!(7),
                    json!([]),
                ] {
                    let mut jwk = row.jwk.clone();
                    jwk["alg"] = alg;
                    assert!(
                        verify(&row, &jwk).is_err(),
                        "{} accepted alg {}",
                        row.name,
                        jwk["alg"]
                    );
                }
            }
        }

        #[test]
        fn purpose_and_key_operations() {
            let row = control();
            verify(&row, &row.jwk).unwrap();
            for purpose in [
                json!("enc"),
                json!("x509-svid"),
                json!("unknown"),
                Value::Null,
                json!(7),
            ] {
                let mut jwk = row.jwk.clone();
                jwk["use"] = purpose;
                assert!(verify(&row, &jwk).is_err(), "accepted use {}", jwk["use"]);
            }
            for ops in [
                json!(["sign"]),
                json!([]),
                json!(["verify", "verify"]),
                Value::Null,
                json!("verify"),
                json!(["verify", 7]),
                json!(["unknown"]),
            ] {
                let mut jwk = row.jwk.clone();
                jwk["key_ops"] = ops;
                assert!(
                    verify(&row, &jwk).is_err(),
                    "accepted operations {}",
                    jwk["key_ops"]
                );
            }
            for op in [
                "encrypt",
                "decrypt",
                "wrapKey",
                "unwrapKey",
                "deriveKey",
                "deriveBits",
            ] {
                let mut jwk = row.jwk.clone();
                jwk["key_ops"] = json!(["verify", op]);
                assert!(
                    verify(&row, &jwk).is_ok(),
                    "omitted use retains mixed-operation compatibility"
                );
                for purpose in ["sig", "jwt-svid"] {
                    jwk["use"] = json!(purpose);
                    assert!(
                        verify(&row, &jwk).is_err(),
                        "accepted contradictory use/key_ops"
                    );
                }
            }
        }

        #[test]
        fn ec_curve_and_public_material() {
            for row in fixtures().into_iter().filter(|r| r.name.starts_with("ec_")) {
                verify(&row, &row.jwk).unwrap();
                for crv in [
                    json!(if row.alg == "ES256" { "P-384" } else { "P-256" }),
                    json!("P-521"),
                    json!("unknown"),
                    Value::Null,
                    json!(7),
                ] {
                    let mut jwk = row.jwk.clone();
                    jwk["crv"] = crv;
                    assert!(verify(&row, &jwk).is_err(), "accepted curve {}", jwk["crv"]);
                }
                for field in ["crv", "kty", "x", "y"] {
                    let mut jwk = row.jwk.clone();
                    jwk.as_object_mut().unwrap().remove(field);
                    assert!(verify(&row, &jwk).is_err(), "accepted absent {field}");
                }
                for field in ["x", "y"] {
                    let bytes =
                        Base64UrlUnpadded::decode_vec(row.jwk[field].as_str().unwrap()).unwrap();
                    for value in [
                        Value::Null,
                        json!(7),
                        json!(""),
                        json!("!"),
                        json!(Base64UrlUnpadded::encode_string(&bytes[..bytes.len() - 1])),
                        json!(Base64UrlUnpadded::encode_string(
                            &[bytes.clone(), vec![0]].concat()
                        )),
                    ] {
                        let mut jwk = row.jwk.clone();
                        jwk[field] = value;
                        assert!(verify(&row, &jwk).is_err(), "accepted invalid {field}");
                    }
                }
                let mut jwk = row.jwk.clone();
                jwk["kty"] = json!("RSA");
                verify(&row, &jwk).unwrap_err();
                let width = if row.alg == "ES256" { 32 } else { 48 };
                jwk = row.jwk.clone();
                jwk["x"] = json!(Base64UrlUnpadded::encode_string(&vec![0; width]));
                jwk["y"] = jwk["x"].clone();
                assert!(
                    verify(&row, &jwk).is_err(),
                    "off-curve point must reach backend rejection"
                );
            }
        }

        #[test]
        fn rsa_significant_modulus_strength_and_backend_capacity() {
            for row in fixtures().into_iter().filter(|r| r.bits != 0) {
                let n = Base64UrlUnpadded::decode_vec(row.jwk["n"].as_str().unwrap()).unwrap();
                assert_eq!(
                    n.len() * 8 - usize::try_from(n[0].leading_zeros()).unwrap(),
                    row.bits
                );
                let result = verify(&row, &row.jwk);
                if row.bits < 2048 {
                    assert!(
                        matches!(result, Err(JwtSvidError::WeakRsaAuthority(bits)) if bits == row.bits),
                        "{} must fail the shared strength policy",
                        row.name
                    );
                } else {
                    let expected = row.bits <= 4096 || cfg!(feature = "jwt-verify-aws-lc-rs");
                    assert_eq!(result.is_ok(), expected, "{}", row.name);
                }
            }
        }

        #[test]
        fn rsa_component_encodings() {
            let rows = fixtures();
            let row = rows.iter().find(|r| r.name == "rsa_2048_RS256").unwrap();
            verify(row, &row.jwk).unwrap();
            for field in ["n", "e"] {
                let bytes =
                    Base64UrlUnpadded::decode_vec(row.jwk[field].as_str().unwrap()).unwrap();
                for value in [
                    Value::Null,
                    json!(7),
                    json!(""),
                    json!("!"),
                    json!("AA"),
                    json!(format!("{}=", row.jwk[field].as_str().unwrap())),
                    json!(Base64UrlUnpadded::encode_string(&[vec![0], bytes].concat())),
                ] {
                    let mut jwk = row.jwk.clone();
                    jwk[field] = value;
                    assert!(verify(row, &jwk).is_err(), "accepted invalid RSA {field}");
                }
                let mut jwk = row.jwk.clone();
                jwk.as_object_mut().unwrap().remove(field);
                verify(row, &jwk).unwrap_err();
            }
            // An unused-bit Base64 alias for exponent 3 must not be canonical.
            let row = rows.iter().find(|r| r.name == "rsa_e3_RS256").unwrap();
            assert_eq!(row.jwk["e"], "Aw");
            verify(row, &row.jwk).unwrap();
            let mut jwk = row.jwk.clone();
            jwk["e"] = json!("Ax");
            verify(row, &jwk).unwrap_err();
            let row = rows.iter().find(|r| r.name == "rsa_1024_RS256").unwrap();
            let n = Base64UrlUnpadded::decode_vec(row.jwk["n"].as_str().unwrap()).unwrap();
            let mut jwk = row.jwk.clone();
            jwk["n"] = json!(Base64UrlUnpadded::encode_string(
                &[vec![0; 128], n].concat()
            ));
            assert!(
                verify(row, &jwk).is_err(),
                "encoded length must not inflate strength"
            );
        }

        #[test]
        fn exact_selection_signature_audience_and_required_claims() {
            for row in fixtures()
                .into_iter()
                .filter(|r| r.name.starts_with("control_"))
            {
                assert!(verify(&row, &row.jwk).is_err(), "{}", row.name);
            }
            let row = control();
            verify(&row, &row.jwk).unwrap();
            JwtSvid::parse_and_validate(&row.token, &bundles(&row.jwk), &["wrong"]).unwrap_err();
            JwtSvid::parse_and_validate::<_, &str>(&row.token, &bundles(&row.jwk), &[])
                .unwrap_err();
            let mut bad = row.jwk.clone();
            bad["key_ops"] = json!(["sign"]);
            let mut alternate = row.jwk.clone();
            alternate["kid"] = json!("alternate");
            let mut bundle = JwtBundle::new(TrustDomain::new("example.org").unwrap());
            bundle
                .add_jwk_authority_json(&serde_json::to_vec(&bad).unwrap())
                .unwrap();
            bundle
                .add_jwk_authority_json(&serde_json::to_vec(&alternate).unwrap())
                .unwrap();
            let mut set: JwtBundleSet = std::iter::once(bundle.clone()).collect();
            JwtSvid::parse_and_validate(&row.token, &set, &["receiver"]).unwrap_err();
            bundle
                .add_jwk_authority_json(&serde_json::to_vec(&row.jwk).unwrap())
                .unwrap();
            set.add_bundle(bundle);
            JwtSvid::parse_and_validate(&row.token, &set, &["receiver"]).unwrap();
            set.add_bundle(JwtBundle::new(TrustDomain::new("example.org").unwrap()));
            assert!(matches!(
                JwtSvid::parse_and_validate(&row.token, &set, &["receiver"]),
                Err(JwtSvidError::AuthorityNotFound(_))
            ));
        }

        mod fixture_generator {
            use super::*;
            include!("testdata/jwt/generate.rs");
        }

        #[test]
        #[ignore = "regenerates public signed fixtures; requires manual review of fixture diff"]
        fn regenerate_authority_policy_fixtures() {
            fixture_generator::generate();
        }
    }
}
