//! JWT SVID types.

use std::str::FromStr;

use jsonwebtoken::jwk::Jwk;
use jsonwebtoken::{Algorithm, DecodingKey, Validation};
use serde::{de, Deserialize, Deserializer, Serialize};
use thiserror::Error;
use zeroize::Zeroize;

use crate::bundle::jwt::JwtBundle;
use crate::spiffe_id::{SpiffeId, SpiffeIdError, TrustDomain};
use crate::BundleSource;
use std::fmt;
use std::marker::PhantomData;
use std::sync::Arc;
use time::OffsetDateTime;

const SUPPORTED_ALGORITHMS: &[Algorithm; 8] = &[
    Algorithm::RS256,
    Algorithm::RS384,
    Algorithm::RS512,
    Algorithm::ES256,
    Algorithm::ES384,
    Algorithm::PS256,
    Algorithm::PS384,
    Algorithm::PS512,
];

/// This type represents a SPIFFE JWT-SVID.
///
/// The serialized token is zeroized on drop.
#[derive(Debug, Clone, PartialEq)]
pub struct JwtSvid {
    spiffe_id: SpiffeId,
    hint: Option<Arc<str>>,
    expiry: OffsetDateTime,
    claims: Claims,
    kid: String,
    alg: Algorithm,
    token: Token,
}

/// An error that can arise trying to parse a [`JwtSvid`] from a JWT token. It also represents
/// errors that can happen validating the token signature or the token audience.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum JwtSvidError {
    /// The 'sub' claim is not a valid SPIFFE ID.
    #[error("invalid spiffe_id in token 'sub' claim")]
    InvalidSubject(#[from] SpiffeIdError),

    /// The header 'kid' is not present.
    #[error("token header 'kid' not found")]
    MissingKeyId,

    /// The header 'typ' contains a value other than 'JWT' or 'JOSE'.
    #[error("token header 'typ' should be 'JWT' or 'JOSE'")]
    InvalidTyp,

    /// The header 'alg' contains an algorithm that is not supported.
    /// Supported algorithms are [`RS256`, `RS384`, `RS512`, `ES256`, `ES384`, `PS256`, `PS384`, `PS512`].
    #[error("algorithm in 'alg' header is not supported")]
    UnsupportedAlgorithm,

    /// Cannot find a JWT bundle for the trust domain, to validate the token signature.
    #[error("cannot find JWT bundle for trust domain: {0}")]
    BundleNotFound(TrustDomain),

    /// Cannot find the JWT authority with `key_id`, to validate the token signature.
    #[error("cannot find JWT authority for key_id: {0}")]
    AuthorityNotFound(String),

    /// The token doesn't have the expected audience.
    #[error("expected audience in {0:?} (audience={1:?})")]
    InvalidAudience(Vec<String>, Vec<String>),

    /// Error returned by the JWT decoding library.
    #[error("cannot decode token")]
    InvalidToken(#[from] jsonwebtoken::errors::Error),

    /// Invalid 'exp' claim value.
    #[error("invalid token expiration ('exp') claim")]
    InvalidExpiration,

    /// Error returned by the bundle source while fetching the bundle.
    #[error("bundle source error")]
    BundleSourceError(#[source] Box<dyn std::error::Error + Send + Sync + 'static>),
}

impl From<std::convert::Infallible> for JwtSvidError {
    fn from(_never: std::convert::Infallible) -> Self {
        unreachable!()
    }
}

#[derive(Debug, Clone, Eq, PartialEq, Zeroize)]
#[zeroize(drop)]
struct Token {
    inner: String,
}

impl From<&str> for Token {
    fn from(token: &str) -> Self {
        Self {
            inner: token.to_owned(),
        }
    }
}

impl AsRef<str> for Token {
    fn as_ref(&self) -> &str {
        self.inner.as_ref()
    }
}

/// Required JWT-SVID claims.
#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct Claims {
    sub: String,
    #[serde(deserialize_with = "string_or_seq_string")]
    aud: Vec<String>,
    exp: i64,
}

impl Claims {
    /// Returns the SPIFFE ID (from the `sub` claim).
    pub fn sub(&self) -> &str {
        &self.sub
    }

    /// Returns the audience (from the `aud` claim).
    pub fn aud(&self) -> &[String] {
        &self.aud
    }

    /// Returns the expiration timestamp (from the `exp` claim).
    pub fn exp(&self) -> i64 {
        self.exp
    }
}

impl JwtSvid {
    /// Parses and validates `token`:
    /// - verifies the signature using the provided bundle source,
    /// - validates the audience against `expected_audience`,
    /// - validates expiration (`exp`).
    ///
    /// # Errors
    ///
    /// Returns [`JwtSvidError`] if:
    /// - the token is malformed or cannot be decoded,
    /// - required headers/claims are missing or invalid (e.g. `kid`, `sub`, `exp`),
    /// - the token uses an unsupported signature algorithm,
    /// - the trust domain bundle or authority (`kid`) cannot be found,
    /// - the signature verification fails,
    /// - the token is expired, or the audience does not match `expected_audience`,
    /// - the bundle source returns an error while fetching bundles.
    pub fn parse_and_validate<B, T>(
        token: &str,
        bundle_source: &B,
        expected_audience: &[T],
    ) -> Result<Self, JwtSvidError>
    where
        B: BundleSource<Item = JwtBundle>,
        B::Error: std::error::Error + Send + Sync + 'static,
        T: AsRef<str> + fmt::Debug,
    {
        // Parse untrusted token to extract trust domain, kid, and alg.
        let untrusted = JwtSvid::parse_insecure(token)?;

        let jwt_authority = JwtSvid::find_jwt_authority(
            bundle_source,
            untrusted.spiffe_id.trust_domain(),
            &untrusted.kid,
        )?;

        let mut validation = Validation::new(untrusted.alg);
        validation.validate_exp = true;

        let aud: Vec<&str> = expected_audience.iter().map(AsRef::as_ref).collect();
        validation.set_audience(&aud);

        let dec_key = DecodingKey::from_jwk(&jwt_authority)?;
        // Perform a validating decode (signature, exp, aud).
        jsonwebtoken::decode::<Claims>(token, &dec_key, &validation)?;

        Ok(untrusted)
    }

    /// Creates a new [`JwtSvid`] from `token` without signature verification.
    ///
    /// IMPORTANT: For parsing and validating the signature of untrusted tokens,
    /// use [`JwtSvid::parse_and_validate`].
    ///
    /// # Errors
    ///
    /// Returns [`JwtSvidError`] if:
    /// - the token is not a valid JWT,
    /// - required claims are missing or malformed,
    /// - the `sub` claim is not a valid SPIFFE ID,
    /// - the `alg` header is unsupported,
    /// - the `typ` header is present but not `JWT` or `JOSE`,
    /// - the `exp` claim is invalid.
    pub fn parse_insecure(token: &str) -> Result<Self, JwtSvidError> {
        JwtSvid::from_str(token)
    }

    /// Returns a copy of this JWT-SVID with the given Workload API hint attached.
    ///
    /// This hint is not part of the JWT; it is metadata returned by the SPIFFE Workload API.
    #[must_use]
    pub fn with_hint(mut self, hint: impl Into<Arc<str>>) -> Self {
        self.hint = Some(hint.into());
        self
    }

    /// Returns the serialized token.
    pub fn token(&self) -> &str {
        self.token.as_ref()
    }

    /// Returns the SPIFFE ID (from the `sub` claim).
    pub fn spiffe_id(&self) -> &SpiffeId {
        &self.spiffe_id
    }

    /// Returns the audience (from the `aud` claim).
    pub fn audience(&self) -> &[String] {
        &self.claims.aud
    }

    /// Returns the token expiration timestamp (from the `exp` claim).
    pub fn expiry(&self) -> OffsetDateTime {
        self.expiry
    }

    /// Returns the `kid` header.
    pub fn key_id(&self) -> &str {
        &self.kid
    }

    /// Returns the parsed claims (untrusted unless validated).
    pub fn claims(&self) -> &Claims {
        &self.claims
    }

    /// Returns the Workload API hint (if any).
    ///
    /// This hint is not part of the JWT; it is metadata returned by the SPIFFE Workload API
    /// when more than one SVID is available.]
    pub fn hint(&self) -> Option<&str> {
        self.hint.as_deref()
    }

    fn find_jwt_authority<B>(
        bundle_source: &B,
        trust_domain: &TrustDomain,
        key_id: &str,
    ) -> Result<Arc<Jwk>, JwtSvidError>
    where
        B: BundleSource<Item = JwtBundle>,
        B::Error: std::error::Error + Send + Sync + 'static,
    {
        let bundle = bundle_source
            .bundle_for_trust_domain(trust_domain)
            .map_err(|e| JwtSvidError::BundleSourceError(Box::new(e)))?
            .ok_or_else(|| JwtSvidError::BundleNotFound(trust_domain.clone()))?;

        bundle
            .find_jwt_authority(key_id) // Option<&Arc<Jwk>>
            .cloned() // Option<Arc<Jwk>>
            .ok_or_else(|| JwtSvidError::AuthorityNotFound(key_id.to_owned()))
    }
}

impl FromStr for JwtSvid {
    type Err = JwtSvidError;

    /// Creates a new [`JwtSvid`] from `token` without signature verification.
    /// Any result from this function is untrusted.
    fn from_str(token: &str) -> Result<Self, Self::Err> {
        // Decode token without signature or expiration validation.
        let mut validation = Validation::default();
        validation.validate_aud = false;
        validation.insecure_disable_signature_validation();

        let token_data =
            jsonwebtoken::decode::<Claims>(token, &DecodingKey::from_secret(&[]), &validation)?;

        let claims = token_data.claims;
        let spiffe_id = SpiffeId::from_str(&claims.sub)?;

        let expiry = OffsetDateTime::from_unix_timestamp(claims.exp)
            .map_err(|_| JwtSvidError::InvalidExpiration)?;

        let kid = token_data.header.kid.ok_or(JwtSvidError::MissingKeyId)?;

        // `typ` is optional; if present, validate it.
        if let Some(t) = token_data.header.typ.as_deref() {
            match t {
                "JWT" | "JOSE" => {}
                _ => return Err(JwtSvidError::InvalidTyp),
            }
        }

        if !SUPPORTED_ALGORITHMS.contains(&token_data.header.alg) {
            return Err(JwtSvidError::UnsupportedAlgorithm);
        }

        Ok(Self {
            spiffe_id,
            hint: None,
            expiry,
            claims,
            kid,
            alg: token_data.header.alg,
            token: Token::from(token),
        })
    }
}

// Used to deserialize 'aud' claim being either a String or a sequence of strings.
// Used to deserialize the 'aud' claim being either a String or a sequence of strings.
fn string_or_seq_string<'de, D>(deserializer: D) -> Result<Vec<String>, D::Error>
where
    D: Deserializer<'de>,
{
    struct StringOrVec(PhantomData<Vec<String>>);

    impl<'de> de::Visitor<'de> for StringOrVec {
        type Value = Vec<String>;

        fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            formatter.write_str("string or sequence of strings")
        }

        fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
        where
            E: de::Error,
        {
            Ok(vec![value.to_owned()])
        }

        fn visit_seq<S>(self, visitor: S) -> Result<Self::Value, S::Error>
        where
            S: de::SeqAccess<'de>,
        {
            Deserialize::deserialize(de::value::SeqAccessDeserializer::new(visitor))
        }
    }

    deserializer.deserialize_any(StringOrVec(PhantomData))
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::bundle::jwt::JwtBundleSet;
    use jsonwebtoken::*;

    #[test]
    fn test_parse_and_validate_jwt_svid() {
        let test_key_id = "test-key-id";

        let test_key = jsonwebkey::Key::generate_p256();

        let encoding_key = jsonwebtoken::EncodingKey::from_ec_der(&test_key.to_der());

        let mut jwt_key = jsonwebkey::JsonWebKey::new(test_key);
        jwt_key.set_algorithm(jsonwebkey::Algorithm::ES256).unwrap();
        jwt_key.key_id = Some(test_key_id.to_string());

        let res = serde_json::to_string(&jwt_key).expect("JWK should be serializable");
        let jwk = serde_json::from_str(&res).expect("JWK should be deserializable");

        let target_audience = vec!["audience".to_owned()];
        // generate signed token
        let token = generate_token(
            target_audience.clone(),
            "spiffe://example.org/service".to_string(),
            Some("JWT".to_string()),
            Some(test_key_id.to_string()),
            4_294_967_295,
            jsonwebtoken::Algorithm::ES256,
            &encoding_key,
        );

        // create a new source of JWT bundles
        let mut bundle_source = JwtBundleSet::default();
        let trust_domain = TrustDomain::new("example.org").unwrap();
        let mut bundle = JwtBundle::new(trust_domain);
        bundle.add_jwt_authority(jwk).unwrap();
        bundle_source.add_bundle(bundle);

        // parse and validate JWT-SVID from signed token using the bundle source to validate the signature
        let jwt_svid = JwtSvid::parse_and_validate(&token, &bundle_source, &["audience"]).unwrap();

        assert_eq!(
            jwt_svid.spiffe_id,
            SpiffeId::new("spiffe://example.org/service").unwrap()
        );

        assert_eq!(jwt_svid.audience(), &target_audience);
        assert_eq!(jwt_svid.token(), token);
    }

    #[test]
    fn test_parse_jwt_svid_with_unsupported_algorithm() {
        let target_audience = vec!["audience".to_owned()];
        let test_key_id = "test-key-id";
        let mut jwt_key = jsonwebkey::JsonWebKey::new(jsonwebkey::Key::generate_p256());
        jwt_key.set_algorithm(jsonwebkey::Algorithm::ES256).unwrap();
        jwt_key.key_id = Some(test_key_id.to_string());

        // generate signed token
        let token = generate_token(
            target_audience,
            "spiffe://example.org/service".to_string(),
            Some("JWT".to_string()),
            Some("some_key_id".to_string()),
            4_294_967_295,
            jsonwebtoken::Algorithm::default(),
            &EncodingKey::from_secret("secret".as_ref()),
        );

        let result = JwtSvid::parse_insecure(&token).unwrap_err();

        assert!(matches!(result, JwtSvidError::UnsupportedAlgorithm));
    }

    #[test]
    fn test_parse_invalid_jwt_svid_without_key_id() {
        let test_key = jsonwebkey::Key::generate_p256();

        let encoding_key = jsonwebtoken::EncodingKey::from_ec_der(&test_key.to_der());

        let target_audience = vec!["audience".to_owned()];
        let test_key_id = "test-key-id";
        let mut jwt_key = jsonwebkey::JsonWebKey::new(test_key);
        jwt_key.set_algorithm(jsonwebkey::Algorithm::ES256).unwrap();
        jwt_key.key_id = Some(test_key_id.to_string());

        // generate signed token
        let token = generate_token(
            target_audience.clone(),
            "spiffe://example.org/service".to_string(),
            Some("JWT".to_string()),
            None,
            4_294_967_295,
            jsonwebtoken::Algorithm::ES256,
            &encoding_key,
        );

        let result = JwtSvid::parse_insecure(&token).unwrap_err();

        assert!(matches!(result, JwtSvidError::MissingKeyId));
    }

    #[test]
    fn test_parse_invalid_jwt_svid_with_invalid_header_typ() {
        let test_key = jsonwebkey::Key::generate_p256();

        let encoding_key = jsonwebtoken::EncodingKey::from_ec_der(&test_key.to_der());

        let target_audience = vec!["audience".to_owned()];
        let test_key_id = "test-key-id";
        let mut jwt_key = jsonwebkey::JsonWebKey::new(test_key);
        jwt_key.set_algorithm(jsonwebkey::Algorithm::ES256).unwrap();
        jwt_key.key_id = Some(test_key_id.to_string());

        // generate signed token
        let token = generate_token(
            target_audience.clone(),
            "spiffe://example.org/service".to_string(),
            Some("OTHER".to_string()),
            Some("kid".to_string()),
            4_294_967_295,
            jsonwebtoken::Algorithm::ES256,
            &encoding_key,
        );

        // parse JWT-SVID from token without validating
        let result = JwtSvid::parse_insecure(&token).unwrap_err();

        assert!(matches!(result, JwtSvidError::InvalidTyp));
    }

    #[test]
    fn test_parse_and_validate_jwt_svid_from_expired_token() {
        let test_key = jsonwebkey::Key::generate_p256();

        let encoding_key = jsonwebtoken::EncodingKey::from_ec_der(&test_key.to_der());

        let target_audience = vec!["audience".to_owned()];
        let test_key_id = "test-key-id";
        let mut jwt_key = jsonwebkey::JsonWebKey::new(test_key);
        jwt_key.set_algorithm(jsonwebkey::Algorithm::ES256).unwrap();
        jwt_key.key_id = Some(test_key_id.to_string());

        let res = serde_json::to_string(&jwt_key).expect("JWK should be serializable");
        let jwk = serde_json::from_str(&res).expect("JWK should be deserializable");

        // generate signed token
        let token = generate_token(
            target_audience.clone(),
            "spiffe://example.org/service".to_string(),
            Some("JWT".to_string()),
            Some(test_key_id.to_string()),
            1,
            jsonwebtoken::Algorithm::ES256,
            &encoding_key,
        );

        // create a new source of JWT bundles
        let mut bundle_source = JwtBundleSet::default();
        let trust_domain = TrustDomain::new("example.org").unwrap();
        let mut bundle = JwtBundle::new(trust_domain);
        bundle.add_jwt_authority(jwk).unwrap();
        bundle_source.add_bundle(bundle);

        // parse and validate JWT-SVID from signed token using the bundle source to validate the signature
        let result =
            JwtSvid::parse_and_validate(&token, &bundle_source, &["audience"]).unwrap_err();

        assert!(matches!(result, JwtSvidError::InvalidToken(..)));
    }

    // used to generate jwt token for testing
    fn generate_token(
        aud: Vec<String>,
        sub: String,
        typ: Option<String>,
        kid: Option<String>,
        exp: i64,
        alg: jsonwebtoken::Algorithm,
        encoding_key: &EncodingKey,
    ) -> String {
        let claims = Claims { sub, aud, exp };

        let header = jsonwebtoken::Header {
            typ,
            alg,
            kid,
            cty: None,
            jku: None,
            x5u: None,
            x5c: None,
            x5t: None,
            jwk: None,
            x5t_s256: None,
        };
        encode(&header, &claims, encoding_key).unwrap()
    }
}
