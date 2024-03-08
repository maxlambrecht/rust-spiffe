//! SPIFFE-ID and TrustDomain types compliant with the SPIFFE standard.

use std::convert::TryFrom;
use std::fmt;
use std::fmt::{Display, Formatter};
use std::str::FromStr;

use thiserror::Error;

const SPIFFE_SCHEME: &str = "spiffe";
const SCHEME_PREFIX: &str = "spiffe://";

const VALID_TRUST_DOMAIN_CHARS: &str = "abcdefghijklmnopqrstuvwxyz0123456789-._";
const VALID_PATH_SEGMENT_CHARS: &str =
    "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-._";

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
    #[error("cannot be empty")]
    Empty,

    /// The trust domain name of SPIFFE ID cannot be empty.
    #[error("trust domain is missing")]
    MissingTrustDomain,

    /// A SPIFFE ID must have a scheme 'spiffe'.
    #[error("scheme is missing or invalid")]
    WrongScheme,

    /// A trust domain name can only contain chars in a limited char set.
    #[error(
        "trust domain characters are limited to lowercase letters, numbers, dots, dashes, and \
         underscores"
    )]
    BadTrustDomainChar,

    /// A path segment can only contain chars in a limited char set.
    #[error(
        "path segment characters are limited to letters, numbers, dots, dashes, and underscores"
    )]
    BadPathSegmentChar,

    /// Path cannot contain empty segments, e.g '//'
    #[error("path cannot contain empty segments")]
    EmptySegment,

    /// Path cannot contain dot segments, e.g '/.', '/..'
    #[error("path cannot contain dot segments")]
    DotSegment,

    /// Path cannot have a trailing slash.
    #[error("path cannot have a trailing slash")]
    TrailingSlash,
}

impl SpiffeId {
    /// Attempts to parse a SPIFFE ID from the given id string.
    ///
    /// # Arguments
    ///
    /// * `id` - A SPIFFE ID, e.g. 'spiffe://trustdomain/path/other'
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
    /// let spiffe_id = SpiffeId::new("spiffe://trustdomain/path").unwrap();
    /// assert_eq!("trustdomain", spiffe_id.trust_domain().to_string());
    /// assert_eq!("/path", spiffe_id.path());
    /// ```
    pub fn new(id: &str) -> Result<Self, SpiffeIdError> {
        if id.is_empty() {
            return Err(SpiffeIdError::Empty);
        }

        if !id.starts_with(SCHEME_PREFIX) {
            return Err(SpiffeIdError::WrongScheme);
        }

        let rest = &id[SCHEME_PREFIX.len()..];
        let i = rest.find('/').unwrap_or(rest.len());

        if i == 0 {
            return Err(SpiffeIdError::MissingTrustDomain);
        }

        let td = &rest[..i];
        if td.chars().any(|c| !is_valid_trust_domain_char(c)) {
            return Err(SpiffeIdError::BadTrustDomainChar);
        }

        let path = &rest[i..];

        if !path.is_empty() {
            validate_path(path)?;
        }

        let trust_domain = TrustDomain {
            name: td.to_string(),
        };
        let path = path.to_string();
        Ok(SpiffeId { trust_domain, path })
    }

    /// Returns a new SPIFFE ID in the given trust domain with joined
    /// path segments. The path segments must be valid according to the SPIFFE
    /// specification and must not contain path separators.
    /// See https://github.com/spiffe/spiffe/blob/main/standards/SPIFFE-ID.md#22-path
    ///
    /// # Arguments
    ///
    /// * `trust_domain` - A [`TrustDomain`] object.
    /// * `segments` - A slice of path segments.
    ///
    /// # Errors
    ///
    /// If the segments contain not allowed characters, a [`SpiffeIdError`] variant will be returned.
    ///
    /// # Examples
    ///
    /// ```
    /// use spiffe::spiffe_id::{SpiffeId, TrustDomain};
    ///
    /// let trust_domain = TrustDomain::new("trustdomain").unwrap();
    /// let spiffe_id = SpiffeId::from_segments(trust_domain, &["path1", "path2", "path3"]).unwrap();
    /// assert_eq!(
    ///     "spiffe://trustdomain/path1/path2/path3",
    ///     spiffe_id.to_string()
    /// );
    /// ```
    pub fn from_segments(
        trust_domain: TrustDomain,
        segments: &[&str],
    ) -> Result<Self, SpiffeIdError> {
        let mut path = String::new();
        for p in segments {
            validate_path(p)?;
            path.push('/');
            path.push_str(p);
        }

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
        Self::new(s)
    }
}

/// Validates that a path string is a conformant path for a SPIFFE ID.
/// See https://github.com/spiffe/spiffe/blob/main/standards/SPIFFE-ID.md#22-path
pub fn validate_path(path: &str) -> Result<(), SpiffeIdError> {
    if path.is_empty() {
        return Err(SpiffeIdError::Empty);
    }

    let chars = path.char_indices().peekable();
    let mut segment_start = 0;

    for (idx, c) in chars {
        if c == '/' {
            match &path[segment_start..idx] {
                "/" => return Err(SpiffeIdError::EmptySegment),
                "/." | "/.." => return Err(SpiffeIdError::DotSegment),
                _ => {}
            }
            segment_start = idx;
            continue;
        }

        if !is_valid_path_segment_char(c) {
            return Err(SpiffeIdError::BadPathSegmentChar);
        }
    }

    match &path[segment_start..] {
        "/" => return Err(SpiffeIdError::TrailingSlash),
        "/." | "/.." => return Err(SpiffeIdError::DotSegment),
        _ => {}
    }

    Ok(())
}

fn is_valid_path_segment_char(c: char) -> bool {
    VALID_PATH_SEGMENT_CHARS.contains(c)
}

impl TrustDomain {
    /// Attempts to parse a TrustDomain instance from the given name or spiffe_id string.
    ///
    /// # Arguments
    ///
    /// * `id_or_name` - Name of a trust domain, it also can be a SPIFFE ID string from which the domain name
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
    /// let trust_domain = TrustDomain::new("domain.test").unwrap();
    /// assert_eq!("domain.test", trust_domain.to_string());
    /// assert_eq!("spiffe://domain.test", trust_domain.id_string());
    ///
    /// let trust_domain = TrustDomain::new("spiffe://example.org/path").unwrap();
    /// assert_eq!("example.org", trust_domain.to_string());
    /// assert_eq!("spiffe://example.org", trust_domain.id_string());
    /// ```
    pub fn new(id_or_name: &str) -> Result<Self, SpiffeIdError> {
        if id_or_name.is_empty() {
            return Err(SpiffeIdError::MissingTrustDomain);
        }

        match id_or_name.find(":/") {
            Some(_) => {
                let spiffe_id = SpiffeId::try_from(id_or_name)?;
                Ok(spiffe_id.trust_domain)
            }
            None => {
                validate_trust_domain_name(id_or_name)?;
                Ok(TrustDomain {
                    name: id_or_name.to_string(),
                })
            }
        }
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

fn validate_trust_domain_name(name: &str) -> Result<(), SpiffeIdError> {
    if name.chars().all(is_valid_trust_domain_char) {
        Ok(())
    } else {
        Err(SpiffeIdError::BadTrustDomainChar)
    }
}

fn is_valid_trust_domain_char(c: char) -> bool {
    VALID_TRUST_DOMAIN_CHARS.contains(c)
}

#[cfg(test)]
mod spiffe_id_tests {
    use std::str::FromStr;

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
        from_valid_spiffe_id_str: (
            "spiffe://trustdomain",
            SpiffeId {
                trust_domain: TrustDomain::from_str("trustdomain").unwrap(),
                path: "".to_string(),
            }
        ),
        from_valid_uri_str: (
            "spiffe://trustdomain/path/element",
            SpiffeId {
                trust_domain: TrustDomain::from_str("trustdomain").unwrap(),
                path: "/path/element".to_string(),
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
        from_str_invalid_uri_str_contains_ip_address: (
            "192.168.2.2:6688",
            SpiffeIdError::WrongScheme,
        ),
        from_str_uri_str_invalid_scheme: (
            "http://domain.test/path/element",
            SpiffeIdError::WrongScheme,
        ),
        from_str_uri_str_empty_authority: (
            "spiffe:/path/element",
            SpiffeIdError::WrongScheme,
        ),
        from_str_uri_str_empty_authority_after_slashes: (
            "spiffe:///path/element",
            SpiffeIdError::MissingTrustDomain,
        ),
        from_str_uri_str_empty_authority_no_slashes: (
            "spiffe:path/element",
            SpiffeIdError::WrongScheme,
        ),
        from_str_uri_str_with_query: (
            "spiffe://domain.test/path/element?query=1",
            SpiffeIdError::BadPathSegmentChar,
        ),
        from_str_uri_str_with_fragment: (
            "spiffe://domain.test/path/element#fragment-1",
            SpiffeIdError::BadPathSegmentChar,
        ),
        from_str_uri_str_with_port: (
            "spiffe://domain.test:8080/path/element",
            SpiffeIdError::BadTrustDomainChar,
        ),
        from_str_uri_str_with_user_info: (
            "spiffe://user:password@test.org/path/element",
            SpiffeIdError::BadTrustDomainChar,
        ),
        from_str_uri_str_with_trailing_slash: (
            "spiffe://test.org/",
            SpiffeIdError::TrailingSlash,
        ),
        from_str_uri_str_with_emtpy_segment: (
            "spiffe://test.org//",
            SpiffeIdError::EmptySegment,
        ),
        from_str_uri_str_with_path_with_trailing_slash: (
            "spiffe://test.org/path/other/",
            SpiffeIdError::TrailingSlash,
        ),
        from_str_uri_str_with_dot_segment: (
            "spiffe://test.org/./other",
            SpiffeIdError::DotSegment,
        ),
        from_str_uri_str_with_double_dot_segment: (
            "spiffe://test.org/../other",
            SpiffeIdError::DotSegment,
        ),
    }

    #[test]
    fn test_parse_with_all_chars() {
        // Go all the way through 255, which ensures we reject UTF-8 appropriately
        for i in 0..=255_u8 {
            let c = i as char;

            // Don't test '/' since it is the delimiter between path segments
            if c == '/' {
                continue;
            }

            let path = format!("/path{}", c);
            let id = format!("spiffe://trustdomain{}", path);

            if VALID_PATH_SEGMENT_CHARS.contains(c) {
                let spiffe_id = SpiffeId::new(&id).unwrap();
                assert_eq!(spiffe_id.to_string(), id)
            } else {
                assert_eq!(
                    SpiffeId::new(&id).unwrap_err(),
                    SpiffeIdError::BadPathSegmentChar
                );
            }

            let td = format!("spiffe://trustdomain{}", c);

            if VALID_TRUST_DOMAIN_CHARS.contains(c) {
                let spiffe_id = SpiffeId::new(&td).unwrap();
                assert_eq!(spiffe_id.to_string(), td)
            } else {
                assert_eq!(
                    SpiffeId::new(&td).unwrap_err(),
                    SpiffeIdError::BadTrustDomainChar
                );
            }
        }
    }

    #[test]
    fn test_from_segments_with_all_chars() {
        // Go all the way through 255, which ensures we reject UTF-8 appropriately
        for i in 0..=255_u8 {
            let c = i as char;

            let path = format!("path{}", c);
            let trust_domain = TrustDomain::new("trustdomain").unwrap();

            if VALID_PATH_SEGMENT_CHARS.contains(c) {
                let spiffe_id = SpiffeId::from_segments(trust_domain, &[path.as_str()]).unwrap();
                assert_eq!(
                    spiffe_id.to_string(),
                    format!("spiffe://trustdomain/{}", path)
                )
            } else if c == '/' {
                assert_eq!(
                    SpiffeId::from_segments(trust_domain, &[path.as_str()]).unwrap_err(),
                    SpiffeIdError::TrailingSlash
                );
            } else {
                assert_eq!(
                    SpiffeId::from_segments(trust_domain, &[path.as_str()]).unwrap_err(),
                    SpiffeIdError::BadPathSegmentChar
                );
            }
        }
    }
}

#[cfg(test)]
mod trust_domain_tests {
    use super::*;
    use std::str::FromStr;

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
        from_str_domain: ("trustdomain", TrustDomain{name: "trustdomain".to_string()}),
        from_str_spiffeid: ("spiffe://other.test", TrustDomain{name: "other.test".to_string()}),
        from_str_spiffeid_with_path: ("spiffe://domain.test/path/element", TrustDomain{name: "domain.test".to_string()}),
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
        from_invalid_scheme:  ("other://domain.test", SpiffeIdError::WrongScheme),
        from_uri_with_port: ("spiffe://domain.test:80", SpiffeIdError::BadTrustDomainChar),
        from_uri_with_userinfo: ("spiffe://user:pass@domain.test", SpiffeIdError::BadTrustDomainChar),
        from_uri_with_invalid_domain: ("spiffe:// domain.test", SpiffeIdError::BadTrustDomainChar),
        from_uri_with_empty_scheme: ("://domain.test", SpiffeIdError::WrongScheme),
        from_uri_with_empty_domain: ("spiffe:///path", SpiffeIdError::MissingTrustDomain),
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
        let trust_domain = TrustDomain::from_str("spiffe://example.org").unwrap();
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

    #[test]
    fn test_parse_with_all_chars() {
        // Go all the way through 255, which ensures we reject UTF-8 appropriately
        for i in 0..=255_u8 {
            let c = i as char;
            let td = format!("trustdomain{}", c);

            if VALID_TRUST_DOMAIN_CHARS.contains(c) {
                let trust_domain = TrustDomain::new(&td).unwrap();
                assert_eq!(trust_domain.to_string(), td)
            } else {
                assert_eq!(
                    TrustDomain::new(&td).unwrap_err(),
                    SpiffeIdError::BadTrustDomainChar
                );
            }
        }
    }
}
