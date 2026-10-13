//! Verification policy for the exact selected trusted authority.

use super::{JwtAlg, JwtSvidError};
use base64ct::{Base64UrlUnpadded, Encoding as _};
use serde_json::Value;
use std::collections::BTreeSet;

pub(super) fn validate(jwk: &Value, algorithm: JwtAlg) -> Result<(), JwtSvidError> {
    if jwk.get("alg").is_some() {
        let declared = JwtAlg::parse(string(jwk, "alg")?)
            .filter(|alg| alg.to_jsonwebtoken().is_some())
            .ok_or(JwtSvidError::InvalidAuthorityMetadata("alg"))?;
        if declared != algorithm {
            return Err(JwtSvidError::AuthorityAlgorithmMismatch {
                authority: declared,
                token: algorithm,
            });
        }
    }

    let explicit_use = jwk.get("use").is_some();
    if explicit_use && !matches!(string(jwk, "use")?, "sig" | "jwt-svid") {
        return Err(JwtSvidError::UnsupportedAuthorityPurpose);
    }
    if let Some(operations) = jwk.get("key_ops") {
        let operations = operations
            .as_array()
            .ok_or(JwtSvidError::InvalidAuthorityMetadata("key_ops"))?;
        let mut seen = BTreeSet::new();
        for operation in operations {
            let operation = operation
                .as_str()
                .ok_or(JwtSvidError::InvalidAuthorityMetadata("key_ops"))?;
            if !seen.insert(operation) {
                return Err(JwtSvidError::InvalidAuthorityMetadata("key_ops"));
            }
            // Unknown extension operations remain compatible. Known encryption
            // or derivation operations contradict an explicit signature purpose.
            if explicit_use
                && matches!(
                    operation,
                    "encrypt" | "decrypt" | "wrapKey" | "unwrapKey" | "deriveKey" | "deriveBits"
                )
            {
                return Err(JwtSvidError::InvalidAuthorityMetadata("key_ops"));
            }
        }
        if !seen.contains("verify") {
            return Err(JwtSvidError::AuthorityVerificationNotPermitted);
        }
    }

    match algorithm {
        JwtAlg::ES256 => validate_ec::<32>(jwk, algorithm, "P-256"),
        JwtAlg::ES384 => validate_ec::<48>(jwk, algorithm, "P-384"),
        JwtAlg::ES512 => Err(JwtSvidError::BackendUnsupportedAlgorithm(algorithm)),
        JwtAlg::RS256
        | JwtAlg::RS384
        | JwtAlg::RS512
        | JwtAlg::PS256
        | JwtAlg::PS384
        | JwtAlg::PS512 => validate_rsa(jwk),
    }
}

fn string<'a>(jwk: &'a Value, field: &'static str) -> Result<&'a str, JwtSvidError> {
    jwk.get(field)
        .and_then(Value::as_str)
        .ok_or(JwtSvidError::InvalidAuthorityMetadata(field))
}

fn validate_ec<const WIDTH: usize>(
    jwk: &Value,
    algorithm: JwtAlg,
    expected_curve: &str,
) -> Result<(), JwtSvidError> {
    if string(jwk, "kty")? != "EC" {
        return Err(JwtSvidError::InvalidAuthorityMetadata("kty"));
    }
    let curve = string(jwk, "crv")?;
    if !matches!(curve, "P-256" | "P-384" | "P-521" | "Ed25519") {
        return Err(JwtSvidError::InvalidAuthorityMetadata("crv"));
    }
    if curve != expected_curve {
        return Err(JwtSvidError::AuthorityCurveMismatch(algorithm));
    }
    for field in ["x", "y"] {
        // Fixed buffers reject oversized coordinates before allocating for them.
        let mut coordinate = [0; WIDTH];
        let bytes = Base64UrlUnpadded::decode(string(jwk, field)?, &mut coordinate)
            .map_err(|_encoding| JwtSvidError::InvalidAuthorityKeyComponent(field))?;
        if bytes.len() != WIDTH {
            return Err(JwtSvidError::InvalidAuthorityKeyComponent(field));
        }
    }
    // The backend still validates the actual point and signature.
    Ok(())
}

fn rsa_component(jwk: &Value, field: &'static str) -> Result<Vec<u8>, JwtSvidError> {
    let bytes = Base64UrlUnpadded::decode_vec(string(jwk, field)?)
        .map_err(|_encoding| JwtSvidError::InvalidAuthorityKeyComponent(field))?;
    match bytes.first() {
        Some(0) if bytes.len() > 1 => Err(JwtSvidError::NonCanonicalRsaComponent(field)),
        None | Some(0) => Err(JwtSvidError::InvalidAuthorityKeyComponent(field)),
        Some(_) => Ok(bytes),
    }
}

fn validate_rsa(jwk: &Value) -> Result<(), JwtSvidError> {
    if string(jwk, "kty")? != "RSA" {
        return Err(JwtSvidError::InvalidAuthorityMetadata("kty"));
    }
    let modulus = rsa_component(jwk, "n")?;
    // Canonical encoding is shared policy; mathematical exponent validity is
    // still checked by the backend. In particular, exponent 3 stays supported.
    let _exponent = rsa_component(jwk, "e")?;
    let significant_first_bits = modulus
        .first()
        .and_then(|first| usize::try_from(8 - first.leading_zeros()).ok())
        .ok_or(JwtSvidError::InvalidAuthorityKeyComponent("n"))?;
    let bits = modulus
        .len()
        .checked_sub(1)
        .and_then(|bytes| bytes.checked_mul(8))
        .and_then(|bits| bits.checked_add(significant_first_bits))
        .ok_or(JwtSvidError::InvalidAuthorityKeyComponent("n"))?;
    if bits < 2048 {
        return Err(JwtSvidError::WeakRsaAuthority(bits));
    }
    // No shared upper bound: retain the backend's existing capacity limits.
    Ok(())
}
