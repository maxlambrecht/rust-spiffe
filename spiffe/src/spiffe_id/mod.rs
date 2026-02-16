//! SPIFFE-ID and `TrustDomain` types compliant with the SPIFFE standard.

use std::fmt;
use std::fmt::{Display, Formatter};
use std::str::FromStr;

use thiserror::Error;

/// The canonical URI scheme name for SPIFFE IDs (`spiffe`).
///
/// Defined by the SPIFFE specification.
pub const SPIFFE_SCHEME: &str = "spiffe";

/// The URI prefix used by SPIFFE IDs.
///
/// This is equivalent to `"{SPIFFE_SCHEME}://"` and is provided as a
/// convenience for prefix checks and parsing.
pub const SPIFFE_SCHEME_PREFIX: &str = "spiffe://";

/// Maximum length for a SPIFFE ID URI in bytes, including the `spiffe://` prefix.
///
/// Per SPIFFE specification: "SPIFFE implementations MUST support SPIFFE URIs up to 2048 bytes
/// in length and SHOULD NOT generate URIs of length greater than 2048 bytes."
/// See: <https://github.com/spiffe/spiffe/blob/main/standards/SPIFFE-ID.md#23-maximum-spiffe-id-length>
const MAX_SPIFFE_ID_URI_LENGTH: usize = 2048;

/// A validated [SPIFFE ID].
///
/// Guarantees that the contained trust domain and path conform to
/// the SPIFFE ID specification:
/// <https://github.com/spiffe/spiffe/blob/main/standards/SPIFFE-ID.md#2-spiffe-identity>.
///
/// Instances of `SpiffeId` are always valid and can be safely compared,
/// formatted, and reused across the API.
#[derive(Debug, Clone, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct SpiffeId {
    trust_domain: TrustDomain,
    path: String,
}

/// A validated SPIFFE trust domain.
///
/// A `TrustDomain` represents the authority component of a SPIFFE ID and
/// is guaranteed to contain only characters allowed by the SPIFFE
/// specification:
/// <https://github.com/spiffe/spiffe/blob/main/standards/SPIFFE-ID.md#21-trust-domain>.
///
/// Trust domains **must be lowercase**. Inputs containing uppercase letters
/// or other disallowed characters are rejected with
/// [`SpiffeIdError::BadTrustDomainChar`] instead of being silently normalized.
///
/// If you accept user-provided trust domain names, normalize them (e.g., convert
/// to lowercase and validate) before constructing a `TrustDomain`.
#[derive(Debug, Clone, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct TrustDomain {
    name: String,
}

/// Errors that can arise parsing a SPIFFE ID.
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

    /// SPIFFE ID URI exceeds maximum allowed length.
    #[error("SPIFFE ID URI exceeds maximum length ({max} bytes)")]
    SpiffeIdTooLong {
        /// Maximum allowed length for a SPIFFE ID URI.
        max: usize,
    },
}

impl SpiffeId {
    /// Attempts to parse a SPIFFE ID from the given id string.
    ///
    /// # Arguments
    ///
    /// * `id` - A SPIFFE ID, e.g. `spiffe://trustdomain/path/other`
    ///
    /// # Errors
    ///
    /// If the function cannot parse the input as a SPIFFE ID, a [`SpiffeIdError`] variant will be returned.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use spiffe::SpiffeId;
    ///
    /// let spiffe_id = SpiffeId::new("spiffe://trustdomain/path").unwrap();
    /// assert_eq!("trustdomain", spiffe_id.trust_domain().to_string());
    /// assert_eq!("/path", spiffe_id.path());
    /// ```
    pub fn new(id: impl AsRef<str>) -> Result<Self, SpiffeIdError> {
        let id = id.as_ref();
        if id.is_empty() {
            return Err(SpiffeIdError::Empty);
        }

        // Enforce total SPIFFE ID URI length limit per SPIFFE specification.
        if id.len() > MAX_SPIFFE_ID_URI_LENGTH {
            return Err(SpiffeIdError::SpiffeIdTooLong {
                max: MAX_SPIFFE_ID_URI_LENGTH,
            });
        }

        let rest = id
            .strip_prefix(SPIFFE_SCHEME_PREFIX)
            .ok_or(SpiffeIdError::WrongScheme)?;

        let (td, path) = match rest.find('/') {
            Some(idx) => rest.split_at(idx),
            None => (rest, ""),
        };

        if td.is_empty() {
            return Err(SpiffeIdError::MissingTrustDomain);
        }

        if !td.as_bytes().iter().all(|&b| is_valid_trust_domain_byte(b)) {
            return Err(SpiffeIdError::BadTrustDomainChar);
        }

        if !path.is_empty() {
            validate_path(path)?;
        }

        Ok(Self {
            trust_domain: TrustDomain {
                name: td.to_string(),
            },
            path: path.to_string(),
        })
    }

    /// Returns a new SPIFFE ID in the given trust domain with joined
    /// path segments. The path segments must be valid according to the SPIFFE
    /// specification and must not contain path separators.
    /// See `https://github.com/spiffe/spiffe/blob/main/standards/SPIFFE-ID.md#22-path`
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
    /// ```no_run
    /// use spiffe::{SpiffeId, TrustDomain};
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
        if segments.is_empty() {
            return Ok(Self {
                trust_domain,
                path: String::new(),
            });
        }

        let total_len: usize = segments.iter().map(|s| s.len()).sum::<usize>() + segments.len();
        let mut path = String::with_capacity(total_len);

        for seg in segments {
            validate_segment(seg)?;
            path.push('/');
            path.push_str(seg);
        }

        // Enforce total SPIFFE ID URI length limit per SPIFFE specification.
        let uri_len = SPIFFE_SCHEME_PREFIX.len() + trust_domain.as_str().len() + path.len();
        if uri_len > MAX_SPIFFE_ID_URI_LENGTH {
            return Err(SpiffeIdError::SpiffeIdTooLong {
                max: MAX_SPIFFE_ID_URI_LENGTH,
            });
        }

        Ok(Self { trust_domain, path })
    }

    /// Returns the trust domain of the SPIFFE ID.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use spiffe::{SpiffeId, TrustDomain};
    ///
    /// let spiffe_id = SpiffeId::new("spiffe://example.org/service")?;
    /// let trust_domain = spiffe_id.trust_domain();
    /// assert_eq!(trust_domain.to_string(), "example.org");
    /// # Ok::<(), Box<dyn std::error::Error>>(())
    /// ```
    pub const fn trust_domain(&self) -> &TrustDomain {
        &self.trust_domain
    }

    /// Returns the trust domain name of this SPIFFE ID.
    ///
    /// This is equivalent to `self.trust_domain().as_str()` and does not
    /// allocate. The returned string is guaranteed to be a valid SPIFFE
    /// trust domain.
    pub fn trust_domain_name(&self) -> &str {
        self.trust_domain.as_str()
    }

    /// Returns the path of the SPIFFE ID.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use spiffe::SpiffeId;
    ///
    /// let spiffe_id = SpiffeId::new("spiffe://example.org/service/api")?;
    /// assert_eq!(spiffe_id.path(), "/service/api");
    ///
    /// let spiffe_id = SpiffeId::new("spiffe://example.org")?;
    /// assert_eq!(spiffe_id.path(), "");
    /// # Ok::<(), Box<dyn std::error::Error>>(())
    /// ```
    pub fn path(&self) -> &str {
        &self.path
    }

    /// Returns `true` if this SPIFFE ID has the given `TrustDomain`.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use spiffe::{SpiffeId, TrustDomain};
    ///
    /// let spiffe_id = SpiffeId::new("spiffe://example.org/service")?;
    /// let trust_domain = TrustDomain::new("example.org")?;
    /// assert!(spiffe_id.is_member_of(&trust_domain));
    ///
    /// let other_domain = TrustDomain::new("other.org")?;
    /// assert!(!spiffe_id.is_member_of(&other_domain));
    /// # Ok::<(), Box<dyn std::error::Error>>(())
    /// ```
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
    fn try_from(s: String) -> Result<Self, Self::Error> {
        Self::new(&s)
    }
}

impl TryFrom<&str> for SpiffeId {
    type Error = SpiffeIdError;
    fn try_from(s: &str) -> Result<Self, Self::Error> {
        Self::new(s)
    }
}

impl TrustDomain {
    /// Attempts to parse a `TrustDomain` instance from the given name or `spiffe_id` string.
    ///
    /// # Arguments
    ///
    /// * `id_or_name` - Name of a trust domain, it also can be a SPIFFE ID string from which the domain name
    ///   is extracted.
    ///
    /// # Errors
    ///
    /// If the function cannot parse the input as a Trust domain, a [`SpiffeIdError`] variant will be returned.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use spiffe::TrustDomain;
    ///
    /// let trust_domain = TrustDomain::new("domain.test").unwrap();
    /// assert_eq!("domain.test", trust_domain.to_string());
    /// assert_eq!("spiffe://domain.test", trust_domain.id_string());
    ///
    /// let trust_domain = TrustDomain::new("spiffe://example.org/path").unwrap();
    /// assert_eq!("example.org", trust_domain.to_string());
    /// assert_eq!("spiffe://example.org", trust_domain.id_string());
    /// ```
    pub fn new(id_or_name: impl AsRef<str>) -> Result<Self, SpiffeIdError> {
        let id_or_name = id_or_name.as_ref();

        if id_or_name.is_empty() {
            return Err(SpiffeIdError::MissingTrustDomain);
        }

        // Fast-path parse if this looks like a SPIFFE ID
        if let Some(rest) = id_or_name.strip_prefix(SPIFFE_SCHEME_PREFIX) {
            if id_or_name.len() > MAX_SPIFFE_ID_URI_LENGTH {
                return Err(SpiffeIdError::SpiffeIdTooLong {
                    max: MAX_SPIFFE_ID_URI_LENGTH,
                });
            }

            let td = rest.split_once('/').map_or(rest, |(td, _path)| td);

            if td.is_empty() {
                return Err(SpiffeIdError::MissingTrustDomain);
            }

            if !td.as_bytes().iter().all(|&b| is_valid_trust_domain_byte(b)) {
                return Err(SpiffeIdError::BadTrustDomainChar);
            }

            return Ok(Self {
                name: td.to_string(),
            });
        }

        if id_or_name.contains(":/") {
            return Err(SpiffeIdError::WrongScheme);
        }

        validate_trust_domain_name(id_or_name)?;
        Ok(Self {
            name: id_or_name.to_string(),
        })
    }

    /// Returns the trust domain name as a string slice.
    ///
    /// This is a borrowed view into the underlying trust domain and does not
    /// allocate. The returned string is guaranteed to be a valid SPIFFE
    /// trust domain according to the specification.
    pub fn as_str(&self) -> &str {
        &self.name
    }

    /// Returns a string representation of the SPIFFE ID of the trust domain,
    /// e.g. `spiffe://example.org`.
    pub fn id_string(&self) -> String {
        let mut s = String::with_capacity(SPIFFE_SCHEME_PREFIX.len() + self.name.len());
        s.push_str(SPIFFE_SCHEME_PREFIX);
        s.push_str(&self.name);
        s
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
        Self::new(name)
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
        Self::new(value)
    }
}

#[inline]
const fn is_valid_trust_domain_byte(b: u8) -> bool {
    matches!(b, b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_')
}

#[inline]
const fn is_valid_path_segment_byte(b: u8) -> bool {
    matches!(b, b'a'..=b'z' | b'A'..=b'Z' | b'0'..=b'9' | b'-' | b'.' | b'_')
}

fn validate_segment(seg: impl AsRef<str>) -> Result<(), SpiffeIdError> {
    let seg = seg.as_ref();

    if seg.is_empty() {
        return Err(SpiffeIdError::EmptySegment);
    }

    if seg.as_bytes().contains(&b'/') {
        return Err(SpiffeIdError::BadPathSegmentChar);
    }

    if seg == "." || seg == ".." {
        return Err(SpiffeIdError::DotSegment);
    }

    if !seg
        .as_bytes()
        .iter()
        .all(|&b| is_valid_path_segment_byte(b))
    {
        return Err(SpiffeIdError::BadPathSegmentChar);
    }

    Ok(())
}

/// Validates that a path string is a conformant SPIFFE ID path.
///
/// Requirements enforced:
/// - non-empty
/// - begins with '/'
/// - no trailing '/'
/// - no empty segments ('//')
/// - no dot segments ('/.', '/..')
/// - only allowed ASCII chars in segments
///
/// Note: Total SPIFFE ID URI length (including spiffe:// prefix and trust domain)
/// is enforced in `SpiffeId::new`, not here. Only validates path format.
fn validate_path(path: &str) -> Result<(), SpiffeIdError> {
    if path.is_empty() {
        return Err(SpiffeIdError::Empty);
    }

    let mut segments = path.split('/');

    if !segments.next().is_some_and(str::is_empty) {
        return Err(SpiffeIdError::BadPathSegmentChar);
    }

    let mut segments = segments.peekable();

    while let Some(segment) = segments.next() {
        if segment.is_empty() {
            return Err(if segments.peek().is_some() {
                SpiffeIdError::EmptySegment
            } else {
                SpiffeIdError::TrailingSlash
            });
        }

        if segment == "." || segment == ".." {
            return Err(SpiffeIdError::DotSegment);
        }

        if !segment
            .as_bytes()
            .iter()
            .all(|&b| is_valid_path_segment_byte(b))
        {
            return Err(SpiffeIdError::BadPathSegmentChar);
        }
    }

    Ok(())
}

fn validate_trust_domain_name(name: &str) -> Result<(), SpiffeIdError> {
    if name
        .as_bytes()
        .iter()
        .all(|&b| is_valid_trust_domain_byte(b))
    {
        Ok(())
    } else {
        Err(SpiffeIdError::BadTrustDomainChar)
    }
}

#[cfg(test)]
mod spiffe_id_tests {
    use super::*;

    macro_rules! spiffe_id_success_tests {
        ($($name:ident: $value:expr_2021,)*) => {
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
                path: String::new(),
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
        ($($name:ident: $value:expr_2021,)*) => {
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
        from_str_uri_str_with_trailing_emtpy_segment: (
            "spiffe://test.org//",
            SpiffeIdError::EmptySegment,
        ),
        from_str_uri_str_with_emtpy_segment_: (
            "spiffe://test.org/path//other",
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
    fn test_parse_with_all_bytes() {
        // Iterate all byte values to ensure we reject non-ASCII and only accept the allowed ASCII set.
        for b in 0u8..=255u8 {
            // Build a UTF-8 string containing this byte.
            // For 0..=127 this is a single ASCII char.
            // For 128..=255 this becomes a Unicode scalar value U+0080..U+00FF encoded as UTF-8,
            // which our ASCII-only validators must reject.
            let c = char::from(b);

            // '/' is the delimiter between path segments
            if c == '/' {
                continue;
            }

            let path = format!("/path{c}");
            let id = format!("spiffe://trustdomain{path}");

            // Expect validity only for allowed ASCII path-segment chars.
            let expect_path_ok = c.is_ascii()
                && matches!(
                    b,
                    b'a'..=b'z'
                        | b'A'..=b'Z'
                        | b'0'..=b'9'
                        | b'-'
                        | b'.'
                        | b'_'
                );

            if expect_path_ok {
                let spiffe_id = SpiffeId::new(&id).unwrap();
                assert_eq!(spiffe_id.to_string(), id);
            } else {
                assert_eq!(
                    SpiffeId::new(&id).unwrap_err(),
                    SpiffeIdError::BadPathSegmentChar
                );
            }

            let td = format!("spiffe://trustdomain{c}");

            // Expect validity only for allowed ASCII trust-domain chars.
            let expect_td_ok = c.is_ascii()
                && matches!(
                    b,
                    b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_'
                );

            if expect_td_ok {
                let spiffe_id = SpiffeId::new(&td).unwrap();
                assert_eq!(spiffe_id.to_string(), td);
            } else {
                assert_eq!(
                    SpiffeId::new(&td).unwrap_err(),
                    SpiffeIdError::BadTrustDomainChar
                );
            }
        }
    }

    #[test]
    fn test_from_segments_uri_length_limit() {
        let td = TrustDomain::new("example.org").unwrap();
        let base_len = SPIFFE_SCHEME_PREFIX.len() + td.as_str().len();
        let per_seg = 2usize; // "/a"

        // Max number of "/a" segments that still fits.
        let allowed_seg_count = (MAX_SPIFFE_ID_URI_LENGTH - base_len) / per_seg;

        // One more segment should exceed the limit.
        let overflow_seg_count = allowed_seg_count + 1;

        let allowed: Vec<&str> = vec!["a"; allowed_seg_count];
        let overflow: Vec<&str> = vec!["a"; overflow_seg_count];

        SpiffeId::from_segments(td.clone(), &allowed).unwrap();
        assert!(matches!(
            SpiffeId::from_segments(td, &overflow),
            Err(SpiffeIdError::SpiffeIdTooLong { .. })
        ));
    }

    #[test]
    fn test_from_segments_with_all_bytes() {
        // Iterate all byte values; for 128..=255 this produces non-ASCII UTF-8,
        // which must be rejected by ASCII-only validation.
        for b in 0u8..=255u8 {
            let c = char::from(b);

            let seg = format!("path{c}");
            let trust_domain = TrustDomain::new("trustdomain").unwrap();

            let expect_ok = c.is_ascii()
                && matches!(
                    b,
                    b'a'..=b'z'
                        | b'A'..=b'Z'
                        | b'0'..=b'9'
                        | b'-'
                        | b'.'
                        | b'_'
                );

            if expect_ok {
                let spiffe_id =
                    SpiffeId::from_segments(trust_domain.clone(), &[seg.as_str()]).unwrap();
                assert_eq!(spiffe_id.to_string(), format!("spiffe://trustdomain/{seg}"));
            } else {
                assert_eq!(
                    SpiffeId::from_segments(trust_domain.clone(), &[seg.as_str()]).unwrap_err(),
                    SpiffeIdError::BadPathSegmentChar
                );
            }
        }
    }
}

#[cfg(test)]
mod trust_domain_tests {
    use super::*;

    macro_rules! trust_domain_success_tests {
        ($($name:ident: $value:expr_2021,)*) => {
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
        ($($name:ident: $value:expr_2021,)*) => {
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
    fn test_trust_domain_parse_with_all_bytes() {
        // Iterate all byte values; for 128..=255 this produces non-ASCII UTF-8,
        // which must be rejected by ASCII-only trust-domain validation.
        for b in 0u8..=255u8 {
            let c = char::from(b);
            let td = format!("trustdomain{c}");

            let expect_ok =
                c.is_ascii() && matches!(b, b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_');

            if expect_ok {
                let trust_domain = TrustDomain::new(&td).unwrap();
                assert_eq!(trust_domain.to_string(), td);
            } else {
                assert_eq!(
                    TrustDomain::new(&td).unwrap_err(),
                    SpiffeIdError::BadTrustDomainChar
                );
            }
        }
    }

    #[test]
    fn trust_domain_as_str() {
        let td = TrustDomain::new("example.org").unwrap();
        assert_eq!(td.as_str(), "example.org");
    }

    #[test]
    fn spiffe_id_trust_domain_name() {
        let id = SpiffeId::new("spiffe://example.org").unwrap();
        assert_eq!(id.trust_domain_name(), "example.org");

        let id = SpiffeId::new("spiffe://example.org/service").unwrap();
        assert_eq!(id.trust_domain_name(), "example.org");
    }

    #[test]
    fn test_spiffe_id_uri_length_limit() {
        let trust_domain = "example.org";
        let prefix_len = SPIFFE_SCHEME_PREFIX.len(); // 11 bytes: "spiffe://"
        let td_len = trust_domain.len();

        // Test with SPIFFE ID at maximum allowed length (2048 bytes total)
        let max_path_len = MAX_SPIFFE_ID_URI_LENGTH - prefix_len - td_len;
        let max_path: String = std::iter::once('/')
            .chain(std::iter::repeat('a'))
            .take(max_path_len)
            .collect();
        let id = format!("spiffe://{trust_domain}{max_path}");
        assert_eq!(id.len(), MAX_SPIFFE_ID_URI_LENGTH);
        assert!(
            SpiffeId::new(&id).is_ok(),
            "SPIFFE ID at max length (2048 bytes) should be accepted"
        );

        // Test with SPIFFE ID exceeding maximum length (2049 bytes)
        let oversized_path: String = std::iter::once('/')
            .chain(std::iter::repeat('a'))
            .take(max_path_len + 1)
            .collect();
        let id = format!("spiffe://{trust_domain}{oversized_path}");
        assert_eq!(id.len(), MAX_SPIFFE_ID_URI_LENGTH + 1);
        let result = SpiffeId::new(&id);
        assert!(
            matches!(result, Err(SpiffeIdError::SpiffeIdTooLong { max: 2048 })),
            "SPIFFE ID exceeding max length should be rejected"
        );

        // Test TrustDomain::new with oversized SPIFFE ID URI (when extracted from full SPIFFE ID)
        let max_td = "a".repeat(MAX_SPIFFE_ID_URI_LENGTH - prefix_len);
        let oversized_id = format!("spiffe://{max_td}a"); // 1 byte over limit
        let result = TrustDomain::new(&oversized_id);
        assert!(
            matches!(result, Err(SpiffeIdError::SpiffeIdTooLong { max: 2048 })),
            "TrustDomain::new should reject oversized SPIFFE ID URI"
        );
    }
}
