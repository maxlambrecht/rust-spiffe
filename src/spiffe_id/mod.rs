//! SPIFFE-ID and TrustDomain types compliant with the SPIFFE standard.

use std::convert::TryFrom;
use std::fmt;
use std::fmt::{Display, Formatter};
use std::str::FromStr;

use thiserror::Error;
use url::{ParseError, Url};

const SPIFFE_SCHEME: &str = "spiffe";
const SPIFFE_ID_MAXIMUM_LENGTH: usize = 2048;
const TRUST_DOMAIN_MAXIMUM_LENGTH: usize = 255;

/// Represents a [SPIFFE ID](https://github.com/spiffe/spiffe/blob/main/standards/SPIFFE-ID.md#2-spiffe-identity).
#[derive(Debug, Clone, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct SpiffeId {
    trust_domain: TrustDomain,
    path: String,
}

/// Represents a [SPIFFE Trust domain](https://github.com/spiffe/spiffe/blob/main/standards/SPIFFE-ID.md#21-trust-domain)
#[derive(Debug, Clone, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct TrustDomain {
    name: String,
}

/// An error that can arise parsing a SPIFFE ID.
#[derive(Debug, Error, PartialEq, Clone)]
#[non_exhaustive]
pub enum SpiffeIdError {
    /// An empty string cannot be parsed as a SPIFFE ID.
    #[error("SPIFFE ID cannot be empty")]
    Empty,

    /// A SPIFFE ID cannot be longer than 2048 characters.
    #[error("SPIFFE ID is too long")]
    IdTooLong,

    /// A SPIFFE ID must have a scheme 'spiffe'.
    #[error("scheme is missing")]
    MissingScheme,

    /// A SPIFFE ID must have a scheme 'spiffe'.
    #[error("invalid scheme")]
    InvalidScheme,

    /// The host component of SPIFFE ID URI cannot be empty.
    #[error("trust domain cannot be empty")]
    MissingTrustDomain,

    /// TrustDomain, i.e. host component in URI cannot be longer than 255 characters.
    #[error("trust domain is too long")]
    TrustDomainTooLong,

    /// A SPIFFE ID URI cannot have a port.
    #[error("port is not allowed")]
    PortNotAllowed,

    /// A SPIFFE ID URI cannot have a query.
    #[error("query is not allowed")]
    QueryNotAllowed,

    /// A SPIFFE ID URI cannot have a fragment.
    #[error("fragment is not allowed")]
    FragmentNotAllowed,

    /// A SPIFFE ID URI cannot have a user info.
    #[error("user info is not allowed")]
    UserInfoNotAllowed,

    /// Error returned by the URI parsing library.
    #[error("failed parsing SPIFFE ID from Uri")]
    CannotParseUri(#[from] ParseError),
}

impl SpiffeId {
    /// Attempts to parse a SPIFFE ID from the given id string.
    ///
    /// # Arguments
    ///
    /// * `id` - A SPIFFE ID, e.g. 'spiffe://example.org/path/subpath'
    ///
    /// # Errors
    ///
    /// If the function cannot parse the input as a SPIFFE ID, a [`SpiffeIdError`] variant will be returned.
    ///
    /// # Examples
    ///
    /// ```
    /// use spiffe::spiffe_id::SpiffeId;
    ///
    /// let spiffe_id = SpiffeId::new("spiffe://example.org/path").unwrap();
    /// assert_eq!("example.org", spiffe_id.trust_domain().to_string());
    /// assert_eq!("/path", spiffe_id.path());
    /// ```
    pub fn new(id: &str) -> Result<Self, SpiffeIdError> {
        let id = id.trim();
        if id.is_empty() {
            return Err(SpiffeIdError::Empty);
        }

        let url = Url::from_str(id)?;
        Self::validate_spiffe_id(&url)?;

        let domain_name = match url.host_str() {
            None => return Err(SpiffeIdError::MissingTrustDomain),
            Some(host) if host.len() > TRUST_DOMAIN_MAXIMUM_LENGTH => {
                return Err(SpiffeIdError::TrustDomainTooLong)
            }
            Some(host) => host.to_lowercase(),
        };

        let trust_domain = TrustDomain { name: domain_name };
        let path = String::from(url.path());
        Ok(SpiffeId { trust_domain, path })
    }

    /// Returns the trust domain of the SPIFFE ID.
    pub fn trust_domain(&self) -> &TrustDomain {
        &self.trust_domain
    }

    /// Returns the path of the SPIFFE ID.
    pub fn path(&self) -> &str {
        &self.path
    }

    /// Returns `true` if this SPIFFE ID has the given TrustDomain.
    pub fn is_member_of(&self, trust_domain: &TrustDomain) -> bool {
        &self.trust_domain == trust_domain
    }

    // Performs the validations to comply with the SPIFFE standard.
    fn validate_spiffe_id(url: &Url) -> Result<(), SpiffeIdError> {
        if url.scheme().is_empty() {
            return Err(SpiffeIdError::MissingScheme);
        }

        if url.scheme() != SPIFFE_SCHEME {
            return Err(SpiffeIdError::InvalidScheme);
        }

        if url.query().is_some() {
            return Err(SpiffeIdError::QueryNotAllowed);
        }

        if url.fragment().is_some() {
            return Err(SpiffeIdError::FragmentNotAllowed);
        }

        if !url.username().is_empty() {
            return Err(SpiffeIdError::UserInfoNotAllowed);
        }

        if url.port().is_some() {
            return Err(SpiffeIdError::PortNotAllowed);
        }

        if url.as_str().len() > SPIFFE_ID_MAXIMUM_LENGTH {
            return Err(SpiffeIdError::IdTooLong);
        }

        Ok(())
    }
}

impl Display for SpiffeId {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "{}://{}{}", SPIFFE_SCHEME, self.trust_domain, self.path)
    }
}

impl FromStr for SpiffeId {
    type Err = SpiffeIdError;

    fn from_str(id: &str) -> Result<Self, Self::Err> {
        Self::new(id)
    }
}

impl TryFrom<String> for SpiffeId {
    type Error = SpiffeIdError;
    fn try_from(s: String) -> Result<SpiffeId, Self::Error> {
        Self::new(s.as_ref())
    }
}

impl TryFrom<&str> for SpiffeId {
    type Error = SpiffeIdError;
    fn try_from(s: &str) -> Result<SpiffeId, Self::Error> {
        Self::from_str(s)
    }
}

impl TrustDomain {
    /// Attempts to parse a TrustDomain instance from the given name.
    ///
    /// The name is normalized to lowercase and cannot be longer than 255 characters.
    ///
    /// # Arguments
    ///
    /// * `name` - Name of the trust domain, it also can be a SPIFFE ID string from which the domain name
    /// is extracted.
    ///
    /// # Errors
    ///
    /// If the function cannot parse the input as a Trust domain, a [`SpiffeIdError`] variant will be returned.
    ///
    /// # Examples
    ///
    /// ```
    /// use spiffe::spiffe_id::TrustDomain;
    ///
    /// let trust_domain = TrustDomain::new("Domain.Test").unwrap();
    /// assert_eq!("domain.test", trust_domain.to_string());
    /// assert_eq!("spiffe://domain.test", trust_domain.id_string());
    ///
    /// let trust_domain = TrustDomain::new("spiffe://example.org/path").unwrap();
    /// assert_eq!("example.org", trust_domain.to_string());
    /// assert_eq!("spiffe://example.org", trust_domain.id_string());
    /// ```
    pub fn new(name: &str) -> Result<Self, SpiffeIdError> {
        let name = name.trim();
        if name.is_empty() {
            return Err(SpiffeIdError::MissingTrustDomain);
        }

        let mut name = name.to_lowercase();
        if !name.contains("://") {
            name = format!("{}://{}", SPIFFE_SCHEME, name);
        }

        let spiffe_id = SpiffeId::try_from(name)?;

        Ok(spiffe_id.trust_domain)
    }

    /// Returns a string representation of the SPIFFE ID of the trust domain,
    /// e.g. "spiffe://example.org".
    pub fn id_string(&self) -> String {
        format!("{}://{}", SPIFFE_SCHEME, self.name)
    }
}

impl Display for TrustDomain {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.name)
    }
}

impl AsRef<str> for TrustDomain {
    fn as_ref(&self) -> &str {
        self.name.as_str()
    }
}

impl FromStr for TrustDomain {
    type Err = SpiffeIdError;

    fn from_str(name: &str) -> Result<Self, Self::Err> {
        TrustDomain::new(name)
    }
}

impl TryFrom<&str> for TrustDomain {
    type Error = SpiffeIdError;

    fn try_from(name: &str) -> Result<Self, Self::Error> {
        Self::new(name)
    }
}

impl TryFrom<String> for TrustDomain {
    type Error = SpiffeIdError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        Self::new(value.as_ref())
    }
}

#[cfg(test)]
mod spiffe_id_tests {
    use std::str::FromStr;

    use url::ParseError;

    use super::*;

    macro_rules! spiffe_id_success_tests {
        ($($name:ident: $value:expr,)*) => {
        $(
            #[test]
            fn $name() {
                let (input, expected) = $value;
                let spiffe_id = SpiffeId::from_str(input).unwrap();
                assert_eq!(spiffe_id, expected);
            }
        )*
        }
    }

    spiffe_id_success_tests! {
        from_valid_uri_str: (
            "spiffe://example.org/path/element",
            SpiffeId {
                trust_domain: TrustDomain::from_str("example.org").unwrap(),
                path: "/path/element".to_string(),
            }
        ),

        from_valid_uri_str_preserve_case_for_path: (
            "spiffe://EXAMPLE.org/PATH/Element",
            SpiffeId {
                trust_domain: TrustDomain::from_str("example.org").unwrap(),
                path: "/PATH/Element".to_string(),
            }
        ),

        from_str_uri_maximum_length: (
            &format!("spiffe://domain.test/{}", "a".repeat(2027)),
            SpiffeId {
                trust_domain: TrustDomain::from_str("domain.test").unwrap(),
                path: format!("/{}","a".repeat(2027)),
            }
        ),
    }

    #[test]
    fn test_is_member_of() {
        let spiffe_id = SpiffeId::from_str("spiffe://example.org").unwrap();
        let trust_domain = TrustDomain::from_str("example.org").unwrap();

        assert!(spiffe_id.is_member_of(&trust_domain));
    }

    #[test]
    fn test_new_from_string() {
        let id_string = String::from("spiffe://example.org/path/element");
        let spiffe_id = SpiffeId::try_from(id_string).unwrap();

        let expected_trust_domain = TrustDomain::from_str("example.org").unwrap();

        assert_eq!(spiffe_id.trust_domain, expected_trust_domain);
        assert_eq!(spiffe_id.path(), "/path/element");
    }

    #[test]
    fn test_to_string() {
        let spiffe_id = SpiffeId::from_str("spiffe://example.org/path/element").unwrap();
        assert_eq!(spiffe_id.to_string(), "spiffe://example.org/path/element");
    }

    #[test]
    fn test_try_from_str() {
        let spiffe_id = SpiffeId::try_from("spiffe://example.org/path").unwrap();

        assert_eq!(
            spiffe_id.trust_domain,
            TrustDomain::from_str("example.org").unwrap()
        );
        assert_eq!(spiffe_id.path, "/path");
    }

    #[test]
    fn test_try_from_string() {
        let spiffe_id = SpiffeId::try_from(String::from("spiffe://example.org/path")).unwrap();

        assert_eq!(
            spiffe_id.trust_domain,
            TrustDomain::from_str("example.org").unwrap()
        );
        assert_eq!(spiffe_id.path, "/path");
    }

    macro_rules! spiffe_id_error_tests {
        ($($name:ident: $value:expr,)*) => {
        $(
            #[test]
            fn $name() {
            let (input, expected_error) = $value;
                let spiffe_id = SpiffeId::from_str(input);
                let error = spiffe_id.unwrap_err();

                assert_eq!(error, expected_error);
            }
        )*
        }
    }

    spiffe_id_error_tests! {
        from_empty_str: ("", SpiffeIdError::Empty),
        from_blank_str: (" ", SpiffeIdError::Empty),
        from_str_invalid_uri_str_contains_ip_address: (
            "192.168.2.2:6688",
            SpiffeIdError::CannotParseUri(ParseError::RelativeUrlWithoutBase),
        ),
        from_str_uri_str_invalid_scheme: (
            "http://domain.test/path/element",
            SpiffeIdError::InvalidScheme,
        ),
        from_str_uri_str_empty_authority: (
            "spiffe:/path/element",
            SpiffeIdError::MissingTrustDomain,
        ),
        from_str_uri_str_empty_authority_after_slashes: (
            "spiffe:///path/element",
            SpiffeIdError::MissingTrustDomain,
        ),
        from_str_uri_str_empty_authority_no_slashes: (
            "spiffe:path/element",
            SpiffeIdError::MissingTrustDomain,
        ),
        from_str_uri_str_with_query: (
            "spiffe://domain.test/path/element?query=1",
            SpiffeIdError::QueryNotAllowed,
        ),
        from_str_uri_str_with_fragment: (
            "spiffe://domain.test/path/element#fragment-1",
            SpiffeIdError::FragmentNotAllowed,
        ),
        from_str_uri_str_with_port: (
            "spiffe://domain.test:8080/path/element",
            SpiffeIdError::PortNotAllowed,
        ),
        from_str_uri_str_with_user_info: (
            "spiffe://user:password@test.org/path/element",
            SpiffeIdError::UserInfoNotAllowed,
        ),
        from_str_uri_exceeds_maximum_length: (
            &format!("spiffe://domain.test/{}", "a".repeat(2028)),
            SpiffeIdError::IdTooLong,
        ),
    }
}

#[cfg(test)]
mod trust_domain_tests {

    use super::*;
    use std::str::FromStr;
    use url::ParseError;

    macro_rules! trust_domain_success_tests {
        ($($name:ident: $value:expr,)*) => {
        $(
            #[test]
            fn $name() {
                let (input, expected) = $value;
                let trust_domain = TrustDomain::new(input).unwrap();
                assert_eq!(trust_domain, expected);
            }
        )*
        }
    }

    trust_domain_success_tests! {
        from_str_domain: ("example.org", TrustDomain{name: "example.org".to_string()}),
        from_str_domain_uppercase: ("  EXAMPLE.org ", TrustDomain{name: "example.org".to_string()}),
        from_str_spiffeid: ("spiffe://other.test", TrustDomain{name: "other.test".to_string()}),
        from_str_spiffeid_with_path: ("spiffe://domain.test/path/element", TrustDomain{name: "domain.test".to_string()}),
        from_str_spiffeid_with_wrapped_uir: ("spiffe://domain.test/spiffe://domain.test:80/path/element", TrustDomain{name: "domain.test".to_string()}),
        from_max_length_str: (&"a".repeat(255), TrustDomain{name: "a".repeat(255)}),
    }

    macro_rules! trust_domain_error_tests {
        ($($name:ident: $value:expr,)*) => {
        $(
            #[test]
            fn $name() {
                let (input, expected_error) = $value;
                let trust_domain = TrustDomain::new(input);
                let error = trust_domain.unwrap_err();
                assert_eq!(error, expected_error);
            }
        )*
        }
    }

    trust_domain_error_tests! {
        from_empty_str: ("", SpiffeIdError::MissingTrustDomain),
        from_empty_blank: ("  ", SpiffeIdError::MissingTrustDomain),
        from_invalid_scheme:  ("other://domain.test", SpiffeIdError::InvalidScheme),
        from_uri_with_port: ("spiffe://domain.test:80", SpiffeIdError::PortNotAllowed),
        from_uri_with_userinfo: ("spiffe://user:pass@domain.test", SpiffeIdError::UserInfoNotAllowed),
        from_uri_with_invalid_domain: ("spiffe:// domain.test", SpiffeIdError::CannotParseUri(ParseError::InvalidDomainCharacter)),
        from_uri_with_empty_scheme: ("://domain.test", SpiffeIdError::CannotParseUri(ParseError::RelativeUrlWithoutBase)),
        from_uri_with_empty_domain: ("spiffe:///path", SpiffeIdError::MissingTrustDomain),
        from_uri_exceeds_maximum_length: (&"a".repeat(256), SpiffeIdError::TrustDomainTooLong),
    }

    #[test]
    fn test_equals() {
        let td_1 = TrustDomain::new("domain.test").unwrap();
        let td_2 = TrustDomain::new("domain.test").unwrap();
        assert_eq!(td_1, td_2);
    }

    #[test]
    fn test_not_equals() {
        let td_1 = TrustDomain::new("domain.test").unwrap();
        let td_2 = TrustDomain::new("other.test").unwrap();
        assert_ne!(td_1, td_2);
    }

    #[test]
    fn test_to_string() {
        let trust_domain = TrustDomain::from_str("example.org").unwrap();
        assert_eq!(trust_domain.to_string(), "example.org");
    }

    #[test]
    fn test_to_id_string() {
        let trust_domain = TrustDomain::from_str("example.org").unwrap();
        assert_eq!(trust_domain.id_string(), "spiffe://example.org");
    }

    #[test]
    fn test_try_from_str() {
        let trust_domain = TrustDomain::try_from("example.org").unwrap();
        assert_eq!(trust_domain.to_string(), "example.org");
    }

    #[test]
    fn test_try_from_string() {
        let trust_domain = TrustDomain::try_from(String::from("example.org")).unwrap();
        assert_eq!(trust_domain.to_string(), "example.org");
    }
}
