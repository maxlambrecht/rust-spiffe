//! JWT SVID types.

use std::str::FromStr;

use jsonwebtoken::jwk::Jwk;
use jsonwebtoken::{Algorithm, DecodingKey, Validation};
use serde::{de, Deserialize, Deserializer, Serialize};
use thiserror::Error;
use zeroize::Zeroize;

use crate::bundle::jwt::JwtBundle;
use crate::bundle::BundleRefSource;
use crate::spiffe_id::{SpiffeId, SpiffeIdError, TrustDomain};
use crate::svid::Svid;
use std::error::Error;
use std::fmt;
use std::marker::PhantomData;
use time::{Date, OffsetDateTime};

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

/// This type represents a [SPIFFE JWT-SVID](https://github.com/spiffe/spiffe/blob/main/standards/JWT-SVID.md).
///
/// The token field is zeroized on drop.
#[derive(Debug, Clone, PartialEq)]
pub struct JwtSvid {
    spiffe_id: SpiffeId,
    expiry: Date,
    // expiry: DateTime<Utc>,
    claims: Claims,
    kid: String,
    alg: Algorithm,

    token: Token,
}

impl Svid for JwtSvid {}

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
    /// Supported algorithms are ['RS256', 'RS384', 'RS512', 'ES256', 'ES384', 'PS256', 'PS384', 'PS512'].
    #[error("algorithm in 'alg' header is not supported")]
    UnsupportedAlgorithm,

    /// One of the required claims is missing. "aud", "sub" and "exp" must be present.
    #[error("one of the required claims ({0}) is missing")]
    RequiredClaimMissing(String),

    /// Cannot find a JWT bundle for the trust domain, to validate the token signature.
    #[error("cannot find JWT bundle for trust domain: {0}")]
    BundleNotFound(TrustDomain),

    /// Cannot find the JWT authority with key_id, to validate the token signature.
    #[error("cannot find JWT authority for key_id: {0}")]
    AuthorityNotFound(String),

    /// The token doesn't have the expected audience.
    #[error("expected audience in {0:?} (audience={1:?})")]
    InvalidAudience(Vec<String>, Vec<String>),

    /// Error returned by the JWT decoding library.
    #[error("cannot decode token")]
    InvalidToken(#[from] jsonwebtoken::errors::Error),

    /// Other errors that can arise.
    #[error("error parsing JWT-SVID")]
    Other(#[from] Box<dyn Error + Send + Sync + 'static>),
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

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
/// Representation of the required
/// [claims](https://github.com/spiffe/spiffe/blob/main/standards/JWT-SVID.md#3-jwt-claims) in a SPIFFE JWT-SVID.
pub struct Claims {
    sub: String,
    #[serde(deserialize_with = "string_or_seq_string")]
    aud: Vec<String>,
    exp: u32,
}

impl Claims {
    /// Get the sub claim.
    pub fn sub(&self) -> &str {
        &self.sub
    }

    /// Get the aud claim.
    pub fn aud(&self) -> &Vec<String> {
        &self.aud
    }

    /// Get the exp claim.
    pub fn exp(&self) -> u32 {
        self.exp
    }
}

impl JwtSvid {
    /// Parses the given token verifying the token signature using the provided [`BundleSource`] as
    /// a source of [`JwtBundle`], validating the audience in the token with the expected audience,
    /// and validating the expiration datetime.
    ///
    /// Returns a validated instance of `JwtSvid`.
    ///
    /// # Arguments
    ///
    /// * `token`: JWT token to parse.
    /// * `bundle_source`: Struct that implements a [`BundleSource`] for the type [`JwtBundle`].
    /// * `expected_audience`: List of audience strings that should be present in the token 'aud' claim.
    ///
    /// # Errors
    ///
    /// If the function cannot parse or verify the signature of the token, a [`JwtSvidError`] variant will be returned.
    pub fn parse_and_validate<T: AsRef<str> + ToString + std::fmt::Debug>(
        token: &str,
        bundle_source: &impl BundleRefSource<Item = JwtBundle>,
        expected_audience: &[T],
    ) -> Result<Self, JwtSvidError> {
        let jwt_svid = JwtSvid::parse_insecure(token)?;

        let jwt_authority = JwtSvid::find_jwt_authority(
            bundle_source,
            jwt_svid.spiffe_id.trust_domain(),
            &jwt_svid.kid,
        )?;

        let mut validation = jsonwebtoken::Validation::new(jwt_svid.alg.to_owned());
        validation.validate_exp = true;
        validation.set_audience(expected_audience);
        let dec_key = DecodingKey::from_jwk(jwt_authority)?;
        jsonwebtoken::decode::<Claims>(token, &dec_key, &validation)?;
        Ok(jwt_svid)
    }

    /// Creates a new [`JwtSvid`] with the given token without signature verification.
    ///
    /// IMPORTANT: For parsing and validating the signature of untrusted tokens, use `parse_and_validate` method.
    pub fn parse_insecure(token: &str) -> Result<Self, JwtSvidError> {
        JwtSvid::from_str(token)
    }

    /// Returns the serialized JWT token.
    pub fn token(&self) -> &str {
        self.token.as_ref()
    }

    /// Returns the SPIFFE ID ('aud' claim) of the token.
    pub fn spiffe_id(&self) -> &SpiffeId {
        &self.spiffe_id
    }

    /// Returns the audience as present in the 'aud' claim.
    pub fn audience(&self) -> &Vec<String> {
        &self.claims.aud
    }

    /// Returns the expiration date of the JWT token.
    pub fn expiry(&self) -> &Date {
        &self.expiry
    }

    /// Returns the key id header of the JWT token.
    pub fn key_id(&self) -> &str {
        &self.kid
    }

    /// Returns the parsed JWT claims (untrusted unless this JWT-SVID was validated).
    pub fn claims(&self) -> &Claims {
        &self.claims
    }

    // Get the bundle associated to the trust_domain in the bundle_source, then from the bundle
    // return the jwt_authority with the key_id
    fn find_jwt_authority<'a>(
        bundle_source: &'a impl BundleRefSource<Item = JwtBundle>,
        trust_domain: &TrustDomain,
        key_id: &str,
    ) -> Result<&'a Jwk, JwtSvidError> {
        let bundle = match bundle_source.get_bundle_for_trust_domain(trust_domain)? {
            None => return Err(JwtSvidError::BundleNotFound(trust_domain.to_owned())),
            Some(b) => b,
        };

        let jwt_authority = bundle
            .find_jwt_authority(key_id)
            .ok_or_else(|| JwtSvidError::AuthorityNotFound(key_id.to_owned()))?;

        Ok(jwt_authority)
    }
}

impl FromStr for JwtSvid {
    type Err = JwtSvidError;

    /// Creates a new [`JwtSvid`] with the given token without signature verification.
    /// Any result from this function is untrusted.
    ///
    /// IMPORTANT: For parsing and validating the signature of untrusted tokens, use `parse_and_validate` method.
    fn from_str(token: &str) -> Result<Self, Self::Err> {
        // decode token without signature or expiration validation
        let mut validation = Validation::default();
        // We later on validate audience separately with `parse_and_validate`
        validation.validate_aud = false;
        validation.insecure_disable_signature_validation();
        let token_data =
            jsonwebtoken::decode::<Claims>(token, &DecodingKey::from_secret(&[]), &validation)?;

        let claims = token_data.claims;
        let spiffe_id = SpiffeId::from_str(&claims.sub)?;

        let expiry = OffsetDateTime::from_unix_timestamp(claims.exp as i64).unwrap();
        let expiry = expiry.date();

        let kid = match token_data.header.kid {
            None => return Err(JwtSvidError::MissingKeyId),
            Some(k) => k,
        };

        match token_data.header.typ {
            None => return Err(JwtSvidError::InvalidTyp),
            Some(t) => match t.as_str() {
                "JWT" => {}
                "JOSE" => {}
                _ => return Err(JwtSvidError::InvalidTyp),
            },
        }

        if !SUPPORTED_ALGORITHMS.contains(&token_data.header.alg) {
            return Err(JwtSvidError::UnsupportedAlgorithm);
        }

        let alg = token_data.header.alg;

        Ok(Self {
            spiffe_id,
            expiry,
            claims,
            kid,
            alg,

            token: Token::from(token),
        })
    }
}

// Used to deserialize 'aud' claim being either a String or a sequence of strings.
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
            4294967295,
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
            4294967295,
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
            4294967295,
            jsonwebtoken::Algorithm::ES256,
            &encoding_key,
        );

        let result = JwtSvid::parse_insecure(&token).unwrap_err();

        assert!(matches!(result, JwtSvidError::MissingKeyId))
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
            4294967295,
            jsonwebtoken::Algorithm::ES256,
            &encoding_key,
        );

        // parse JWT-SVID from token without validating
        let result = JwtSvid::parse_insecure(&token).unwrap_err();

        assert!(matches!(result, JwtSvidError::InvalidTyp))
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
        exp: u32,
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
