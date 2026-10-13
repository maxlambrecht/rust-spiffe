#[expect(
    clippy::too_many_lines,
    reason = "one manual fixture generation procedure"
)]
pub(super) fn generate() {
    use openssl::bn::{BigNum, BigNumContext};
    use openssl::ec::{EcGroup, EcKey};
    use openssl::ecdsa::EcdsaSig;
    use openssl::hash::MessageDigest;
    use openssl::nid::Nid;
    use openssl::pkey::{PKey, Private};
    use openssl::rsa::{Padding, Rsa};
    use openssl::sign::{RsaPssSaltlen, Signer, Verifier};

    fn signed(key: &PKey<Private>, alg: &str, header: &Value, claims: &Value) -> String {
        let digest = match alg {
            "ES256" | "RS256" | "PS256" => MessageDigest::sha256(),
            "ES384" | "RS384" | "PS384" => MessageDigest::sha384(),
            "RS512" | "PS512" => MessageDigest::sha512(),
            _ => panic!("unsupported fixture algorithm"),
        };
        let input = format!(
            "{}.{}",
            Base64UrlUnpadded::encode_string(header.to_string().as_bytes()),
            Base64UrlUnpadded::encode_string(claims.to_string().as_bytes())
        );
        let mut signer = Signer::new(digest, key).unwrap();
        let mut verifier = Verifier::new(digest, key).unwrap();
        if alg.starts_with("PS") {
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
        assert!(
            verifier.verify(&signature).unwrap(),
            "independent signature verification"
        );
        let signature = if alg.starts_with("ES") {
            let width = if alg == "ES256" { 32 } else { 48 };
            let sig = EcdsaSig::from_der(&signature).unwrap();
            [
                sig.r().to_vec_padded(width).unwrap(),
                sig.s().to_vec_padded(width).unwrap(),
            ]
            .concat()
        } else {
            signature
        };
        format!("{input}.{}", Base64UrlUnpadded::encode_string(&signature))
    }

    let claims = json!({"sub":"spiffe://example.org/workload","aud":"receiver","exp":i64::from(u32::MAX),
        "private":{"roles":["read"],"nested":{"x":true}}});
    let header = |alg: &str| json!({"alg":alg,"kid":"probe","typ":"JWT"});
    let mut rows = Vec::new();
    for (alg, nid, width) in [
        ("ES256", Nid::X9_62_PRIME256V1, 32),
        ("ES384", Nid::SECP384R1, 48),
    ] {
        let group = EcGroup::from_curve_name(nid).unwrap();
        let ec = EcKey::generate(&group).unwrap();
        let mut ctx = BigNumContext::new().unwrap();
        let (mut x, mut y) = (BigNum::new().unwrap(), BigNum::new().unwrap());
        ec.public_key()
            .affine_coordinates_gfp(&group, &mut x, &mut y, &mut ctx)
            .unwrap();
        let jwk = json!({"kty":"EC","kid":"probe","crv":if width == 32 {"P-256"} else {"P-384"},
            "x":Base64UrlUnpadded::encode_string(&x.to_vec_padded(width).unwrap()),
            "y":Base64UrlUnpadded::encode_string(&y.to_vec_padded(width).unwrap())});
        let key = PKey::from_ec_key(ec).unwrap();
        rows.push(
            json!({"name":format!("ec_{alg}"),"alg":alg,"bits":0,"jwk":jwk,
            "token":signed(&key,alg,&header(alg),&claims)}),
        );
        if alg == "ES256" {
            for field in ["sub", "aud", "exp"] {
                let mut c = claims.clone();
                c.as_object_mut().unwrap().remove(field);
                rows.push(
                    json!({"name":format!("control_missing_{field}"),"alg":alg,"bits":0,"jwk":jwk,
                    "token":signed(&key,alg,&header(alg),&c)}),
                );
            }
            for (name, field, value) in [
                ("expired", "exp", json!(1)),
                ("domain", "sub", json!("spiffe://foreign.org/workload")),
                ("audience", "aud", json!("wrong")),
                ("empty_audience", "aud", json!([])),
            ] {
                let mut c = claims.clone();
                c[field] = value;
                rows.push(
                    json!({"name":format!("control_{name}"),"alg":alg,"bits":0,"jwk":jwk,
                    "token":signed(&key,alg,&header(alg),&c)}),
                );
            }
            let attacker = PKey::from_ec_key(EcKey::generate(&group).unwrap()).unwrap();
            rows.push(
                json!({"name":"control_wrong_signature","alg":alg,"bits":0,"jwk":jwk,
                "token":signed(&attacker,alg,&header(alg),&claims)}),
            );
            let mut h = header(alg);
            h["kid"] = json!("missing");
            rows.push(
                json!({"name":"control_wrong_kid","alg":alg,"bits":0,"jwk":jwk,
                "token":signed(&key,alg,&h,&claims)}),
            );
        }
    }
    for (bits, exponent) in [
        (1024, 0x0001_0001),
        (1536, 0x0001_0001),
        (2040, 0x0001_0001),
        (2047, 0x0001_0001),
        (2048, 0x0001_0001),
        (3072, 0x0001_0001),
        (4096, 0x0001_0001),
        (5120, 0x0001_0001),
        (2048, 3),
    ] {
        let rsa = Rsa::generate_with_e(bits, &BigNum::from_u32(exponent).unwrap()).unwrap();
        assert_eq!(u32::try_from(rsa.n().num_bits()).unwrap(), bits);
        let jwk = json!({"kty":"RSA","kid":"probe",
            "n":Base64UrlUnpadded::encode_string(&rsa.n().to_vec()),
            "e":Base64UrlUnpadded::encode_string(&rsa.e().to_vec())});
        let key = PKey::from_rsa(rsa).unwrap();
        for alg in ["RS256", "RS384", "RS512", "PS256", "PS384", "PS512"] {
            if bits == 1024 && alg == "PS512" {
                continue;
            }
            rows.push(json!({"name":if exponent == 3 {format!("rsa_e3_{alg}")} else {format!("rsa_{bits}_{alg}")},
                "alg":alg,"bits":bits,"jwk":jwk,"token":signed(&key,alg,&header(alg),&claims)}));
        }
    }
    let mut serialized = serde_json::to_string_pretty(&rows).unwrap();
    serialized.push('\n');
    std::fs::write(
        concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/testdata/jwt/authority-policy.json"
        ),
        serialized,
    )
    .unwrap();
}
