//! JWT bundle types.

use crate::spiffe_id::TrustDomain;
use crate::BundleSource;
use jsonwebtoken::jwk::{Jwk, JwkSet};
use std::collections::HashMap;
use std::convert::Infallible;
use std::sync::Arc;
use thiserror::Error;

/// This type contains a collection of trusted JWT authorities (Public keys) for a `TrustDomain`.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct JwtBundle {
    trust_domain: TrustDomain,
    jwt_authorities: HashMap<String, Arc<Jwk>>,
}

/// This type contains a set of [`JwtBundle`], keyed by [`TrustDomain`].
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct JwtBundleSet {
    bundles: HashMap<TrustDomain, Arc<JwtBundle>>,
}

/// An error that can arise creating a new [`JwtBundle`].
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum JwtBundleError {
    /// The JWT authority misses the key ID that identifies it.
    #[error("missing key ID")]
    MissingKeyId,
    /// There was a problem deserializing bytes into a Json JWT keys set.
    #[error("cannot deserialize json jwk set")]
    Deserialize(#[from] serde_json::Error),
}

impl JwtBundle {
    /// Creates an empty `JwtBundle` for the given `TrustDomain`.
    pub fn new(trust_domain: TrustDomain) -> Self {
        Self {
            trust_domain,
            jwt_authorities: HashMap::new(),
        }
    }

    /// Parses a `JwtBundle` from bytes representing a set of  JWT authorities. The data must be
    /// a standard RFC 7517 JWTK document.
    ///
    /// # Arguments
    ///
    /// * `trust_domain` -  A [`TrustDomain`] to associate to the bundle.
    /// * `jwt_authorities` -  A slice of bytes representing a set of JWT authorities in a standard RFC 7517 JWKS document.
    ///
    /// # Errors
    ///
    /// If the function cannot parse the bytes into a JSON `WebKey` Set, a [`JwtBundleError`] variant will be returned.
    ///
    /// # Examples
    ///
    /// ```
    /// use spiffe::{JwtBundle, TrustDomain};
    ///
    /// let jwt_authorities = r#"{
    ///     "keys": [
    ///         {
    ///             "kty": "EC",
    ///             "kid": "C6vs25welZOx6WksNYfbMfiw9l96pMnD",
    ///             "crv": "P-256",
    ///             "x": "ngLYQnlfF6GsojUwqtcEE3WgTNG2RUlsGhK73RNEl5k",
    ///             "y": "tKbiDSUSsQ3F1P7wteeHNXIcU-cx6CgSbroeQrQHTLM"
    ///         }
    ///     ]
    ///  }"#
    /// .as_bytes();
    /// let trust_domain = TrustDomain::new("example.org").unwrap();
    /// let jwt_bundle = JwtBundle::from_jwt_authorities(trust_domain, jwt_authorities).unwrap();
    ///
    /// assert!(
    ///     jwt_bundle
    ///         .find_jwt_authority("C6vs25welZOx6WksNYfbMfiw9l96pMnD")
    ///         .is_some()
    /// );
    /// ```
    pub fn from_jwt_authorities(
        trust_domain: TrustDomain,
        jwt_authorities: &[u8],
    ) -> Result<Self, JwtBundleError> {
        let jwk_set: JwkSet = serde_json::from_slice(jwt_authorities)?;

        let mut authorities: HashMap<String, Arc<Jwk>> = HashMap::new();
        for key in jwk_set.keys {
            let key_id = key
                .common
                .key_id
                .as_deref()
                .ok_or(JwtBundleError::MissingKeyId)?;

            authorities.insert(key_id.to_owned(), Arc::new(key));
        }

        Ok(Self {
            trust_domain,
            jwt_authorities: authorities,
        })
    }

    /// Returns the [`JwtAuthority`] with the given key ID.
    pub fn find_jwt_authority(&self, key_id: &str) -> Option<&Arc<Jwk>> {
        self.jwt_authorities.get(key_id)
    }

    /// Adds a [`JwtAuthority`] to the bundle.
    ///
    /// # Errors
    ///
    /// Returns a [`JwtBundleError::MissingKeyId`] if the authority does not contain
    /// a key ID.
    pub fn add_jwt_authority(&mut self, authority: Jwk) -> Result<(), JwtBundleError> {
        let key_id = authority
            .common
            .key_id
            .as_deref()
            .ok_or(JwtBundleError::MissingKeyId)?
            .to_owned();

        self.jwt_authorities.insert(key_id, Arc::new(authority));
        Ok(())
    }

    /// Returns the [`TrustDomain`] associated to the bundle.
    pub fn trust_domain(&self) -> &TrustDomain {
        &self.trust_domain
    }
}

impl JwtBundleSet {
    /// Creates an empty JWT bundle set.
    pub fn new() -> Self {
        Self {
            bundles: HashMap::new(),
        }
    }

    /// Adds a new [`JwtBundle`] into the set. If a bundle already exists for the
    /// trust domain, the existing bundle is replaced.
    pub fn add_bundle(&mut self, bundle: JwtBundle) {
        let trust_domain = bundle.trust_domain().clone();
        self.bundles.insert(trust_domain, Arc::new(bundle));
    }

    /// Returns the [`JwtBundle`] associated with the given [`TrustDomain`].
    pub fn bundle_for(&self, trust_domain: &TrustDomain) -> Option<&Arc<JwtBundle>> {
        self.bundles.get(trust_domain)
    }
}

impl Default for JwtBundleSet {
    fn default() -> Self {
        Self::new()
    }
}

impl BundleSource for JwtBundleSet {
    type Item = JwtBundle;
    type Error = Infallible;

    fn bundle_for_trust_domain(
        &self,
        trust_domain: &TrustDomain,
    ) -> Result<Option<Arc<Self::Item>>, Self::Error> {
        Ok(self.bundles.get(trust_domain).cloned())
    }
}

#[cfg(test)]
mod jwt_bundle_test {

    use super::*;

    #[test]
    fn test_parse_bundle_from_json_single_authority() {
        let bundle_bytes = r#"{
        "keys": [
        {
            "kty": "EC",
            "kid": "C6vs25welZOx6WksNYfbMfiw9l96pMnD",
            "crv": "P-256",
            "x": "ngLYQnlfF6GsojUwqtcEE3WgTNG2RUlsGhK73RNEl5k",
            "y": "tKbiDSUSsQ3F1P7wteeHNXIcU-cx6CgSbroeQrQHTLM"
        }
    ]
}"#
        .as_bytes();
        let trust_domain = TrustDomain::new("example.org").unwrap();
        let jwt_bundle = JwtBundle::from_jwt_authorities(trust_domain, bundle_bytes).unwrap();
        assert!(jwt_bundle
            .find_jwt_authority("C6vs25welZOx6WksNYfbMfiw9l96pMnD")
            .is_some());
    }

    #[test]
    fn test_parse_bundle_from_json_multiple_authorities() {
        let bundle_bytes = r#"{
  "keys": [
    {
      "kty": "EC",
      "kid": "C6vs25welZOx6WksNYfbMfiw9l96pMnD",
      "crv": "P-256",
      "x": "ngLYQnlfF6GsojUwqtcEE3WgTNG2RUlsGhK73RNEl5k",
      "y": "tKbiDSUSsQ3F1P7wteeHNXIcU-cx6CgSbroeQrQHTLM"
    },
    {
      "kty": "EC",
      "kid": "gHTCunJbefYtnZnTctd84xeRWyMrEsWD",
      "crv": "P-256",
      "x": "7MGOl06DP9df2u8oHY6lqYFIoQWzCj9UYlp-MFeEYeY",
      "y": "PSLLy5Pg0_kNGFFXq_eeq9kYcGDM3MPHJ6ncteNOr6w"
    }
  ]
}"#
        .as_bytes();

        let trust_domain = TrustDomain::new("example.org").unwrap();
        let jwt_bundle = JwtBundle::from_jwt_authorities(trust_domain, bundle_bytes).unwrap();
        assert!(jwt_bundle
            .find_jwt_authority("C6vs25welZOx6WksNYfbMfiw9l96pMnD")
            .is_some());
        assert!(jwt_bundle
            .find_jwt_authority("gHTCunJbefYtnZnTctd84xeRWyMrEsWD")
            .is_some());
    }

    #[test]
    fn test_parse_bundle_from_authority_missing_key_id() {
        let bundle_bytes = r#"{{
    "keys": [
        {
            "kty": "EC",
            "kid": "C6vs25welZOx6WksNYfbMfiw9l96pMnD",
            "crv": "P-256",
            "x": "ngLYQnlfF6GsojUwqtcEE3WgTNG2RUlsGhK73RNEl5k",
            "y": "tKbiDSUSsQ3F1P7wteeHNXIcU-cx6CgSbroeQrQHTLM"
        },
        {
            "kty": "EC",
            "crv": "P-256",
            "x": "7MGOl06DP9df2u8oHY6lqYFIoQWzCj9UYlp-MFeEYeY",
            "y": "PSLLy5Pg0_kNGFFXq_eeq9kYcGDM3MPHJ6ncteNOr6w"
        }
    ]
}"#
        .as_bytes();

        let trust_domain = TrustDomain::new("example.org").unwrap();
        let result = JwtBundle::from_jwt_authorities(trust_domain, bundle_bytes);

        assert!(matches!(
            result.unwrap_err(),
            JwtBundleError::Deserialize(..)
        ));
    }

    #[test]
    fn test_parse_jwks_with_empty_keys_array() {
        let bundle_bytes = r#"{"keys": []}"#.as_bytes();
        let trust_domain = TrustDomain::new("domain.test").unwrap();
        let jwt_bundle = JwtBundle::from_jwt_authorities(trust_domain, bundle_bytes)
            .expect("Failed to parse JWKS with empty keys array");

        assert!(
            jwt_bundle.jwt_authorities.is_empty(),
            "JWT authorities should be empty"
        );
    }
}
