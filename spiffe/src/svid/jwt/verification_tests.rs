//! Signed regressions use the same verification body as the public method, with
//! a private clock seam for boundaries. Public-path cases exercise the real clock.

use super::*;
use crate::bundle::jwt::JwtBundleSet;
use base64ct::{Base64UrlUnpadded, Encoding as _};
use openssl::bn::{BigNum, BigNumContext};
use openssl::ec::{EcGroup, EcKey};
use openssl::ecdsa::EcdsaSig;
use openssl::hash::MessageDigest;
use openssl::nid::Nid;
use openssl::pkey::{PKey, Private};
use openssl::rsa::{Padding, Rsa};
use openssl::sign::{RsaPssSaltlen, Signer, Verifier};
use std::time::{Duration, UNIX_EPOCH};

const N: i64 = 2_000_000_000;
const HEADER: &str = r#"{"alg":"ES256","kid":"k1"}"#;

#[cfg(feature = "jwt-source")]
#[path = "source_regression_tests.rs"]
mod source_regressions;

struct Fixture {
    key: PKey<Private>,
    bundles: JwtBundleSet,
}

impl Fixture {
    fn ec(nid: Nid, curve: &str) -> Self {
        let group = EcGroup::from_curve_name(nid).unwrap();
        let key = EcKey::generate(&group).unwrap();
        let mut x = BigNum::new().unwrap();
        let mut y = BigNum::new().unwrap();
        key.public_key()
            .affine_coordinates_gfp(&group, &mut x, &mut y, &mut BigNumContext::new().unwrap())
            .unwrap();
        let width = usize::try_from(group.degree().div_ceil(8)).unwrap();
        let jwk = serde_json::json!({"kid":"k1", "kty":"EC", "crv":curve,
            "x":b64(&padded(&x, width)), "y":b64(&padded(&y, width))});
        Self::new(PKey::from_ec_key(key).unwrap(), &jwk)
    }

    fn es256() -> Self {
        Self::ec(Nid::X9_62_PRIME256V1, "P-256")
    }

    fn rsa() -> Self {
        let key = Rsa::generate(2048).unwrap();
        let jwk = serde_json::json!({"kid":"k1", "kty":"RSA",
            "n":b64(&key.n().to_vec()), "e":b64(&key.e().to_vec())});
        Self::new(PKey::from_rsa(key).unwrap(), &jwk)
    }

    fn new(key: PKey<Private>, jwk: &serde_json::Value) -> Self {
        let authority = JwtAuthority::from_jwk_json(&serde_json::to_vec(jwk).unwrap()).unwrap();
        let mut bundle = JwtBundle::new(TrustDomain::new("example.org").unwrap());
        bundle.add_jwt_authority(authority);
        let mut bundles = JwtBundleSet::default();
        bundles.add_bundle(bundle);
        Self { key, bundles }
    }

    fn sign(&self, alg: JwtAlg, header: &str, payload: &str) -> String {
        let input = format!("{}.{}", b64(header.as_bytes()), b64(payload.as_bytes()));
        let digest = match alg {
            JwtAlg::ES256 | JwtAlg::RS256 | JwtAlg::PS256 => MessageDigest::sha256(),
            JwtAlg::ES384 | JwtAlg::RS384 | JwtAlg::PS384 => MessageDigest::sha384(),
            JwtAlg::RS512 | JwtAlg::PS512 => MessageDigest::sha512(),
            _ => panic!("unsupported fixture algorithm"),
        };
        let mut signer = Signer::new(digest, &self.key).unwrap();
        let mut verifier = Verifier::new(digest, &self.key).unwrap();
        if matches!(alg, JwtAlg::PS256 | JwtAlg::PS384 | JwtAlg::PS512) {
            signer.set_rsa_padding(Padding::PKCS1_PSS).unwrap();
            signer.set_rsa_mgf1_md(digest).unwrap();
            signer
                .set_rsa_pss_saltlen(RsaPssSaltlen::DIGEST_LENGTH)
                .unwrap();
            verifier.set_rsa_padding(Padding::PKCS1_PSS).unwrap();
            verifier.set_rsa_mgf1_md(digest).unwrap();
            verifier
                .set_rsa_pss_saltlen(RsaPssSaltlen::DIGEST_LENGTH)
                .unwrap();
        }
        signer.update(input.as_bytes()).unwrap();
        let signature = signer.sign_to_vec().unwrap();
        verifier.update(input.as_bytes()).unwrap();
        assert!(verifier.verify(&signature).unwrap(), "fixture signature");
        let signature = match alg {
            JwtAlg::ES256 | JwtAlg::ES384 => {
                let width = if alg == JwtAlg::ES256 { 32 } else { 48 };
                let sig = EcdsaSig::from_der(&signature).unwrap();
                [padded(sig.r(), width), padded(sig.s(), width)].concat()
            }
            _ => signature,
        };
        format!("{input}.{}", b64(&signature))
    }

    fn token(&self, exp: i64, nbf: Option<&str>) -> String {
        self.sign(JwtAlg::ES256, HEADER, &payload(exp, nbf))
    }

    fn validate(&self, token: &str, nanos: u32) -> Result<JwtSvid, JwtSvidError> {
        JwtSvid::parse_and_validate_with_clock(token, &self.bundles, &["audience"], || {
            UNIX_EPOCH + Duration::new(u64::try_from(N).unwrap(), nanos)
        })
    }
}

fn b64(bytes: &[u8]) -> String {
    Base64UrlUnpadded::encode_string(bytes)
}

fn padded(value: &openssl::bn::BigNumRef, width: usize) -> Vec<u8> {
    let bytes = value.to_vec();
    let mut padded = vec![0; width - bytes.len()];
    padded.extend(bytes);
    padded
}

fn payload(exp: i64, nbf: Option<&str>) -> String {
    let nbf = nbf.map_or_else(String::new, |v| format!(",\"nbf\":{v}"));
    format!(r#"{{"sub":"spiffe://example.org/service","aud":"audience","exp":{exp}{nbf}}}"#)
}

fn assert_kind(result: Result<JwtSvid, JwtSvidError>, kind: JwtVerificationErrorKind) {
    let error = result.unwrap_err();
    let JwtSvidError::InvalidToken(error) = error else {
        panic!("expected {kind:?}, got {error:?}");
    };
    assert_eq!(error.kind(), kind);
}

#[test]
fn jwt_temporal_nbf_activation() {
    let fixture = Fixture::es256();
    for value in [
        None,
        Some("1999999999"),
        Some("2000000000"),
        Some("1999999999.75"),
        Some("-1"),
        Some("-0.25"),
        Some("2000000000.0"),
        Some("2e9"),
        Some("2E+9"),
        Some("2000000000.000e+0"),
        Some(" 2000000000 \n"),
        Some("200000000000e-2"),
    ] {
        assert!(
            fixture.validate(&fixture.token(N + 600, value), 0).is_ok(),
            "nbf={value:?}"
        );
    }
    for value in [
        "2000000001",
        "2000001800",
        "2000000000.25",
        "2000000000.75",
        "2.00000000025e9",
        "2000000000.000000001",
    ] {
        assert_kind(
            fixture.validate(&fixture.token(N + 600, Some(value)), 0),
            JwtVerificationErrorKind::NotYetValid,
        );
    }
    let token = fixture.token(N + 1, Some("2000000000.25"));
    assert_kind(
        fixture.validate(&token, 249_999_999),
        JwtVerificationErrorKind::NotYetValid,
    );
    fixture.validate(&token, 250_000_000).unwrap();
    fixture.validate(&token, 750_000_000).unwrap();
    let token = fixture.token(N + 1, Some("2000000000.000000100"));
    assert_kind(
        fixture.validate(&token, 99),
        JwtVerificationErrorKind::NotYetValid,
    );
    fixture.validate(&token, 100).unwrap();
}

#[test]
fn jwt_temporal_malformed_and_out_of_range_nbf() {
    let fixture = Fixture::es256();
    for value in [
        "null",
        "\"later\"",
        "\"2000000000\"",
        "true",
        "false",
        "[]",
        "{}",
        "[2000000000]",
        "{\"time\":2000000000}",
        "18446744073709551615",
        "-9223372036854775808",
        "1e100",
        "1e309",
        "1e-100",
        "1e2147483648",
        "1e-2147483649",
        "9007199254740993",
        "2000000000.0000000001",
        "253402300800",
        "253402300799.9999999991",
        "-377705116800.000000001",
        "-377705116801",
    ] {
        let error = fixture
            .validate(&fixture.token(N + 600, Some(value)), 0)
            .unwrap_err();
        assert!(
            matches!(error, JwtSvidError::InvalidNotBefore),
            "nbf={value}: {error:?}"
        );
    }
    // Exact nanoseconds, signed dates, exponent notation, and trailing zeros.
    for value in [
        "-377705116800",
        "-377705116799.999999999",
        "-0",
        "-0.000000001",
        "0e100",
        "2000000000.0000000000",
        "20000000000000000000000000000000000000000e-31",
        "20000000000000000000000000000000000000000.0e-31",
    ] {
        assert!(
            fixture
                .validate(&fixture.token(N + 600, Some(value)), 0)
                .is_ok(),
            "nbf={value}"
        );
    }
    for value in ["253402300799.999999999", "253402300799999999999e-9"] {
        assert_kind(
            fixture.validate(&fixture.token(N + 600, Some(value)), 0),
            JwtVerificationErrorKind::NotYetValid,
        );
    }
    let claims_json = format!(
        r#"{{"sub":"spiffe://example.org/service","aud":"audience","exp":{},"nbf":null,"nbf":0}}"#,
        N + 600
    );
    assert!(matches!(
        fixture.validate(&fixture.sign(JwtAlg::ES256, HEADER, &claims_json), 0),
        Err(JwtSvidError::InvalidNotBefore)
    ));
}

#[test]
fn jwt_temporal_expiration_exclusive() {
    let fixture = Fixture::es256();
    for exp in [N - 1, N] {
        for nanos in [0, 500_000_000, 999_999_999] {
            assert_kind(
                fixture.validate(&fixture.token(exp, None), nanos),
                JwtVerificationErrorKind::Expired,
            );
        }
    }
    for nanos in [0, 500_000_000, 999_999_999] {
        fixture
            .validate(&fixture.token(N + 1, None), nanos)
            .unwrap();
    }
    fixture.validate(&fixture.token(N + 600, None), 0).unwrap();
    fixture
        .validate(&fixture.token(N + 1, Some("2000000000.5")), 500_000_000)
        .unwrap();
    assert_kind(
        fixture.validate(&fixture.token(N, Some("2000000000")), 0),
        JwtVerificationErrorKind::Expired,
    );
    for exp in [
        "null",
        "\"2000000001\"",
        "true",
        "[]",
        "{}",
        "2000000001.0",
        "2000000001.5",
        "9223372036854775808",
    ] {
        let claims_json =
            format!(r#"{{"sub":"spiffe://example.org/service","aud":"audience","exp":{exp}}}"#);
        assert!(matches!(
            fixture.validate(&fixture.sign(JwtAlg::ES256, HEADER, &claims_json), 0),
            Err(JwtSvidError::InvalidJson(_))
        ));
    }
    let missing = r#"{"sub":"spiffe://example.org/service","aud":"audience"}"#;
    assert!(matches!(
        fixture.validate(&fixture.sign(JwtAlg::ES256, HEADER, missing), 0),
        Err(JwtSvidError::InvalidJson(_))
    ));
}

#[test]
fn jwt_jose_header_allowlist_public_path() {
    let fixture = Fixture::es256();
    let claims_json = payload(0xFFFF_FFFF, None);
    for header in [
        HEADER,
        r#"{"alg":"ES256","kid":"k1","typ":"JWT"}"#,
        r#"{"alg":"ES256","kid":"k1","typ":"JOSE"}"#,
    ] {
        let token = fixture.sign(JwtAlg::ES256, header, &claims_json);
        JwtSvid::parse_and_validate(&token, &fixture.bundles, &["audience"]).unwrap();
    }
    for extra in [
        r#""typ":null"#,
        r#""typ":true"#,
        r#""typ":0"#,
        r#""typ":[]"#,
        r#""typ":{}"#,
        r#""crit":["private"],"private":true"#,
        r#""crit":["b64"],"b64":false"#,
        r#""crit":["absent"]"#,
        r#""crit":[]"#,
        r#""crit":null"#,
        r#""crit":true"#,
        r#""b64":false"#,
        r#""b64":true"#,
        r#""b64":null"#,
        r#""jku":"http://127.0.0.1/unused""#,
        r#""jwk":{"kty":"EC"}"#,
        r#""x5u":"http://127.0.0.1/unused""#,
        r#""x5c":["unused"]"#,
        r#""x5t":"unused""#,
        r#""x5t#S256":"unused""#,
        r#""cty":"JWT""#,
        r#""private":{"nested":true}"#,
        r#""private":1,"private":2"#,
    ] {
        let header = format!(r#"{{"alg":"ES256","kid":"k1",{extra}}}"#);
        let token = fixture.sign(JwtAlg::ES256, &header, &claims_json);
        let error =
            JwtSvid::parse_and_validate(&token, &fixture.bundles, &["audience"]).unwrap_err();
        assert!(
            matches!(error, JwtSvidError::InvalidJoseHeader(_)),
            "{extra}: {error:?}"
        );
    }
}

#[test]
fn jwt_jose_supported_field_errors() {
    let fixture = Fixture::es256();
    for header in [
        r#"{"kid":"k1"}"#,
        r#"{"alg":null,"kid":"k1"}"#,
        r#"{"alg":1,"kid":"k1"}"#,
        r#"{"alg":true,"kid":"k1"}"#,
        r#"{"alg":[],"kid":"k1"}"#,
        r#"{"alg":{},"kid":"k1"}"#,
        r#"{"alg":"ES256","kid":true}"#,
        r#"{"alg":"ES256","kid":1}"#,
        r#"{"alg":"ES256","kid":[]}"#,
        r#"{"alg":"ES256","kid":{}}"#,
        r#"{"alg":"ES256","alg":"ES256","kid":"k1"}"#,
        r#"{"alg":"ES256","kid":"k1","kid":"k1"}"#,
        r#"{"alg":"ES256","kid":"k1","typ":"JWT","typ":"JOSE"}"#,
        r#"{"alg":"ES256","kid":"k1","typ":null,"typ":"JWT"}"#,
    ] {
        let token = fixture.sign(JwtAlg::ES256, header, &payload(N + 600, None));
        assert!(
            matches!(
                fixture.validate(&token, 0),
                Err(JwtSvidError::InvalidJoseHeader(_))
            ),
            "{header}"
        );
    }
    for header in [r#"{"alg":"ES256"}"#, r#"{"alg":"ES256","kid":null}"#] {
        let token = fixture.sign(JwtAlg::ES256, header, &payload(N + 600, None));
        assert!(matches!(
            fixture.validate(&token, 0),
            Err(JwtSvidError::MissingKeyId)
        ));
    }
    let token = fixture.sign(
        JwtAlg::ES256,
        r#"{"alg":"ES256","kid":"k1","typ":"OTHER"}"#,
        &payload(N + 600, None),
    );
    assert!(matches!(
        fixture.validate(&token, 0),
        Err(JwtSvidError::InvalidTyp)
    ));
}

#[test]
fn jwt_temporal_public_path_and_parse_only_compatibility() {
    let fixture = Fixture::es256();
    for nbf in [
        "4000000000",
        "4000000000.25",
        "null",
        "\"later\"",
        "[]",
        "{}",
    ] {
        let token = fixture.token(0xFFFF_FFFF, Some(nbf));
        JwtSvid::parse_insecure(&token).unwrap();
        JwtSvid::from_workload_api_token(&token).unwrap();
        token.parse::<JwtSvid>().unwrap();
        let result = JwtSvid::parse_and_validate(&token, &fixture.bundles, &["audience"]);
        if matches!(nbf, "4000000000" | "4000000000.25") {
            assert_kind(result, JwtVerificationErrorKind::NotYetValid);
        } else {
            assert!(matches!(result, Err(JwtSvidError::InvalidNotBefore)));
        }
    }
    let token = fixture.sign(
        JwtAlg::ES256,
        r#"{"alg":"ES256","kid":"k1","typ":null,"private":true}"#,
        &payload(N + 600, None),
    );
    JwtSvid::parse_insecure(&token).unwrap();
    JwtSvid::from_workload_api_token(&token).unwrap();
    token.parse::<JwtSvid>().unwrap();
    assert_kind(
        JwtSvid::parse_and_validate(&fixture.token(1, None), &fixture.bundles, &["audience"]),
        JwtVerificationErrorKind::Expired,
    );
}

#[test]
fn jwt_verification_controls_and_private_claims() {
    let fixture = Fixture::es256();
    let claims_json = r#"{"sub":"spiffe://example.org/service","aud":"audience","exp":2000000600,"iat":"unrestricted","iss":{"private":true},"extra":{"roles":["reader"]}}"#;
    let token = fixture.sign(JwtAlg::ES256, HEADER, claims_json);
    fixture.validate(&token, 0).unwrap();
    for audience in [vec!["wrong"], vec![]] {
        assert_kind(
            JwtSvid::parse_and_validate_with_clock(&token, &fixture.bundles, &audience, || {
                UNIX_EPOCH + Duration::from_secs(N.try_into().unwrap())
            }),
            JwtVerificationErrorKind::AudienceMismatch,
        );
    }
    for (claims_json, expected) in [
        (
            payload(N + 600, None).replace("example.org", "other.org"),
            "domain",
        ),
        (payload(N + 600, None), "key"),
    ] {
        let header = if expected == "key" {
            r#"{"alg":"ES256","kid":"unknown"}"#
        } else {
            HEADER
        };
        let error = fixture
            .validate(&fixture.sign(JwtAlg::ES256, header, &claims_json), 0)
            .unwrap_err();
        if expected == "domain" {
            assert!(matches!(error, JwtSvidError::BundleNotFound(_)));
        } else {
            assert!(matches!(error, JwtSvidError::AuthorityNotFound(_)));
        }
    }
    for claim in ["sub", "aud", "exp"] {
        let mut claims_json: serde_json::Value =
            serde_json::from_str(&payload(N + 600, None)).unwrap();
        claims_json.as_object_mut().unwrap().remove(claim);
        assert!(matches!(
            fixture.validate(
                &fixture.sign(JwtAlg::ES256, HEADER, &claims_json.to_string()),
                0
            ),
            Err(JwtSvidError::InvalidJson(_))
        ));
    }
    let attacker = Fixture::es256();
    let token = attacker.token(N + 600, Some("2000000001"));
    assert_kind(
        fixture.validate(&token, 0),
        JwtVerificationErrorKind::InvalidSignature,
    );
    let token = attacker.token(N + 600, None);
    assert_kind(
        fixture.validate(&token, 0),
        JwtVerificationErrorKind::InvalidSignature,
    );
}

#[test]
fn jwt_verification_supported_asymmetric_algorithms() {
    let rsa = Fixture::rsa();
    for alg in [
        JwtAlg::RS256,
        JwtAlg::RS384,
        JwtAlg::RS512,
        JwtAlg::PS256,
        JwtAlg::PS384,
        JwtAlg::PS512,
    ] {
        let header = format!(r#"{{"alg":"{alg:?}","kid":"k1"}}"#);
        assert!(
            rsa.validate(&rsa.sign(alg, &header, &payload(N + 600, Some("-1"))), 0)
                .is_ok(),
            "{alg:?}"
        );
    }
    let es384 = Fixture::ec(Nid::SECP384R1, "P-384");
    let header = r#"{"alg":"ES384","kid":"k1"}"#;
    es384
        .validate(
            &es384.sign(JwtAlg::ES384, header, &payload(N + 600, None)),
            0,
        )
        .unwrap();
}

#[test]
fn jwt_temporal_clock_read_once_and_failure() {
    let fixture = Fixture::es256();
    let token = fixture.token(N + 1, Some("2000000000.25"));
    let calls = std::cell::Cell::new(0);
    JwtSvid::parse_and_validate_with_clock(&token, &fixture.bundles, &["audience"], || {
        calls.set(calls.get() + 1);
        UNIX_EPOCH + Duration::new(N.try_into().unwrap(), 250_000_000)
    })
    .unwrap();
    assert_eq!(calls.get(), 1);
    for now in [
        UNIX_EPOCH - Duration::from_nanos(1),
        UNIX_EPOCH + Duration::from_secs(253_402_300_800),
    ] {
        assert!(matches!(
            JwtSvid::parse_and_validate_with_clock(&token, &fixture.bundles, &["audience"], || now),
            Err(JwtSvidError::InvalidVerificationTime)
        ));
    }
}
