//! SPIFFE endpoint parsing and validation.
//!
//! Defines a SPIFFE-specific endpoint abstraction used by SPIFFE-related APIs
//! (SPIFFE Workload API, SPIRE Agent Admin API). Not a general-purpose networking endpoint.
//!
//! Unix paths are percent-decoded once into filesystem paths. See [`Endpoint::parse`].

use std::net::IpAddr;
use std::path::PathBuf;
use std::str::FromStr;

use thiserror::Error;
use url::Url;

const TCP_SCHEME: &str = "tcp";
const UNIX_SCHEME: &str = "unix";

/// Parsed SPIFFE endpoint.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum Endpoint {
    /// UNIX domain socket endpoint (POSIX systems).
    Unix(PathBuf),

    /// TCP endpoint (host must be an IP address).
    Tcp {
        /// IP address of the endpoint.
        host: IpAddr,
        /// TCP port of the endpoint.
        port: u16,
    },
}

/// An error returned when an endpoint cannot be parsed as a URI.
///
/// This wrapper is transparent. Formatting it formats the underlying URL
/// parser error, and [`std::error::Error::source`] returns that error's
/// source. The underlying error type is not part of this crate's public API
/// and may change between releases.
#[derive(Debug, Error)]
#[error(transparent)]
pub struct EndpointParseError {
    source: url::ParseError,
}

impl EndpointParseError {
    const fn new(source: url::ParseError) -> Self {
        Self { source }
    }
}

/// Errors returned by [`Endpoint::parse`].
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum EndpointError {
    /// The input could not be parsed as a valid URI.
    #[error("endpoint socket is not a valid URI")]
    Parse(#[source] EndpointParseError),

    /// The URI scheme is not supported.
    #[error("endpoint socket URI scheme must be unix: or tcp:")]
    InvalidScheme,

    /// User info (`user:pass@...`) is not allowed.
    #[error("endpoint socket URI must not include user info")]
    HasUserInfo,

    /// Query values are not allowed.
    #[error("endpoint socket URI must not include query values")]
    HasQuery,

    /// Fragments are not allowed.
    #[error("endpoint socket URI must not include a fragment")]
    HasFragment,

    /// UNIX endpoints must not include an authority/host.
    #[error("unix: endpoint socket URI must not include an authority")]
    UnixAuthorityNotAllowed,

    /// UNIX endpoints must include a non-empty path.
    #[error("unix: endpoint socket URI must include a path")]
    UnixMissingPath,

    /// TCP endpoints must use an IP address (not a hostname).
    #[error("tcp: endpoint socket URI host must be an IP address")]
    TcpHostNotIp,

    /// TCP endpoints must include a port.
    #[error("tcp: endpoint socket URI must include a port")]
    TcpMissingPort,

    /// TCP endpoints must not include a non-empty path.
    #[error("tcp: endpoint socket URI must not include a path")]
    TcpUnexpectedPath,

    /// The Unix endpoint contains a raw ASCII control or leading or trailing space.
    ///
    /// Raw controls are rejected instead of being stripped or re-encoded. A
    /// percent-encoded control other than NUL is path data; see [`Endpoint::parse`].
    #[error("unix: endpoint socket path contains an invalid character")]
    UnixInvalidCharacter,

    /// A `%` in the Unix path is not followed by two hexadecimal digits.
    #[error("unix: endpoint socket path contains a malformed percent escape")]
    UnixBadPercentEscape,

    /// The Unix path percent-encodes `/`, which is a separator rather than data.
    #[error("unix: endpoint socket path must not percent-encode a path separator")]
    UnixEncodedSeparator,

    /// The Unix path percent-encodes a NUL byte.
    #[error("unix: endpoint socket path must not contain a NUL byte")]
    UnixEncodedNul,

    /// The Unix path percent-decodes to bytes that are not UTF-8.
    #[error("unix: endpoint socket path is not valid UTF-8")]
    UnixPathNotUtf8,
}

impl Endpoint {
    /// Parse and validate a SPIFFE endpoint URI.
    ///
    /// `SPIFFE_ENDPOINT_SOCKET` and `SPIRE_ADMIN_ENDPOINT_SOCKET` use this
    /// grammar. There is one Unix path rule for both.
    ///
    /// ## Unix
    ///
    /// Accepted forms, with a case-insensitive `unix` scheme:
    ///
    /// - `unix:///absolute/path` — empty authority, as in the Workload Endpoint example
    /// - `unix:/absolute/path` — the same absolute path with the authority omitted
    ///
    /// The path component is an absolute filesystem path. After the structural
    /// checks, `%XX` is decoded once and that UTF-8 string becomes the
    /// [`PathBuf`] passed to `connect`. Decoding happens after splitting on
    /// literal `/`, so an encoded slash is not a separator. `.` and `..`
    /// segments and repeated slashes are kept for the operating system.
    ///
    /// A literal space, quotation mark, caret, or other non-delimiter octet is
    /// path data. `unix:///tmp/agent sock` and `unix:///tmp/agent%20sock` name
    /// the same socket. Those raw octets are outside the strict RFC 3986
    /// alphabet; a filename space at either end of the whole endpoint must be
    /// written `%20`, and a literal `%` must be written `%25`.
    ///
    /// Raw ASCII controls (U+0000–U+001F and U+007F) are rejected, including tab
    /// and newline. The same octets are path data when percent-encoded, except
    /// NUL (`%00`), which is rejected in both forms. `%2F` and `%2f` are
    /// rejected. A `%` that is not two hex digits is rejected, as are decoded
    /// bytes that are not UTF-8.
    ///
    /// A non-empty authority, user info, query, fragment, or non-absolute path
    /// is rejected. `unix:tmp/sock`, `unix://`, and `unix:///` are rejected.
    ///
    /// ## TCP
    ///
    /// - `tcp://<ip>:<port>`
    /// - `tcp:<ip>:<port>` (accepted in practice)
    ///
    /// The host must be an IP address. An empty path is allowed. Any other
    /// path, user info, query, or fragment is rejected. A percent-encoded host
    /// that is not an IP address is rejected. TCP parsing is otherwise unchanged.
    ///
    /// ## Errors
    ///
    /// Returns an [`EndpointError`] if:
    /// - the input is not a valid URI,
    /// - the URI scheme is not supported,
    /// - the URI contains user info, query values, or a fragment,
    /// - the endpoint does not satisfy the validation rules for its scheme.
    pub fn parse(input: &str) -> Result<Self, EndpointError> {
        let normalized = normalize_endpoint_uri(input);
        let url = Url::parse(&normalized)
            .map_err(|source| EndpointError::Parse(EndpointParseError::new(source)))?;

        if !url.username().is_empty() || url.password().is_some() {
            return Err(EndpointError::HasUserInfo);
        }
        if url.query().is_some() {
            return Err(EndpointError::HasQuery);
        }
        if url.fragment().is_some() {
            return Err(EndpointError::HasFragment);
        }

        match url.scheme() {
            UNIX_SCHEME => parse_unix_endpoint(&normalized, &url),

            TCP_SCHEME => {
                let host = match url.host() {
                    Some(url::Host::Ipv4(ipv4)) => IpAddr::V4(ipv4),
                    Some(url::Host::Ipv6(ipv6)) => IpAddr::V6(ipv6),
                    Some(url::Host::Domain(domain)) => {
                        // Try parsing as IP address (IPv4 might be parsed as Domain by url crate)
                        IpAddr::from_str(domain).map_err(
                            |std::net::AddrParseError { .. }| EndpointError::TcpHostNotIp,
                        )?
                    }
                    None => return Err(EndpointError::TcpHostNotIp),
                };
                let port = url.port().ok_or(EndpointError::TcpMissingPort)?;

                let path = url.path();
                if !path.is_empty() && path != "/" {
                    return Err(EndpointError::TcpUnexpectedPath);
                }

                Ok(Self::Tcp { host, port })
            }

            _ => Err(EndpointError::InvalidScheme),
        }
    }
}

impl FromStr for Endpoint {
    type Err = EndpointError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::parse(s)
    }
}

fn normalize_endpoint_uri(input: &str) -> String {
    // Accept the shorthand `unix:/path` by rewriting it into a valid URL.
    if let Some(input) = input.strip_prefix("unix:/") {
        if !input.starts_with('/') {
            return format!("unix:///{input}");
        }
    }

    // Accept the shorthand `tcp:IP:PORT` by rewriting it into a valid URL.
    if let Some(input) = input.strip_prefix("tcp:") {
        if !input.starts_with("//") {
            return format!("tcp://{input}");
        }
    }

    input.to_owned()
}

/// Unix filesystem path for `normalized`, which is the string passed to `Url::parse`.
///
/// `Url::path()` is the WHATWG serialization: it percent-encodes bytes outside
/// its path set and removes `.` and `..` segments. That string is a different
/// file from the path the URI denotes, so `connect` must not receive it.
///
/// The slice is taken only after checks that `Url` would otherwise rewrite.
/// `Url` trims leading and trailing C0 controls and spaces, and it skips tab,
/// LF, and CR anywhere. Those inputs are rejected first. The region scan then
/// enforces the Unix structure on the same bytes it slices, so the path never
/// depends on how `Url` serialized the input.
fn parse_unix_endpoint(normalized: &str, url: &Url) -> Result<Endpoint, EndpointError> {
    if url.host_str().is_some() {
        return Err(EndpointError::UnixAuthorityNotAllowed);
    }
    if unix_endpoint_has_forbidden_chars(normalized) {
        return Err(EndpointError::UnixInvalidCharacter);
    }

    let path = unix_path_region(normalized)?;
    if path.is_empty() || path == "/" {
        return Err(EndpointError::UnixMissingPath);
    }

    // `path` starts with a literal `/` and is longer than one byte, so the
    // decoded string is also absolute and is not exactly `/`.
    let decoded = decode_unix_path(path)?;
    Ok(Endpoint::Unix(PathBuf::from(decoded)))
}

fn unix_endpoint_has_forbidden_chars(input: &str) -> bool {
    let bytes = input.as_bytes();
    bytes.first() == Some(&b' ')
        || bytes.last() == Some(&b' ')
        || bytes.iter().any(u8::is_ascii_control)
}

/// Path substring of a Unix endpoint that contains no ASCII controls and no
/// leading or trailing space. The result is empty or starts with `/`.
fn unix_path_region(input: &str) -> Result<&str, EndpointError> {
    // `Url` already reported the `unix` scheme. A mismatch here means the two
    // views of the input disagree, so fail closed.
    let Some((scheme, rest)) = input.split_once(':') else {
        return Err(EndpointError::UnixInvalidCharacter);
    };
    if !scheme.eq_ignore_ascii_case(UNIX_SCHEME) {
        return Err(EndpointError::UnixInvalidCharacter);
    }

    let path = if let Some(after_slashes) = rest.strip_prefix("//") {
        // `find` returns a char boundary, so the split cannot panic.
        let authority_end = after_slashes
            .find(['/', '?', '#'])
            .unwrap_or(after_slashes.len());
        let (authority, path) = after_slashes.split_at(authority_end);
        // `Url` drops empty user info (`unix://:@/path`) and reports no host,
        // so a non-empty authority can reach this point.
        if authority.contains('@') {
            return Err(EndpointError::HasUserInfo);
        }
        if !authority.is_empty() {
            return Err(EndpointError::UnixAuthorityNotAllowed);
        }
        path
    } else if rest.starts_with('/') {
        rest
    } else {
        return Err(EndpointError::UnixMissingPath);
    };

    if path.contains('?') {
        return Err(EndpointError::HasQuery);
    }
    if path.contains('#') {
        return Err(EndpointError::HasFragment);
    }
    Ok(path)
}

fn decode_unix_path(path: &str) -> Result<String, EndpointError> {
    let bytes = path.as_bytes();
    let mut decoded = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while let Some(&byte) = bytes.get(index) {
        if byte != b'%' {
            decoded.push(byte);
            index += 1;
            continue;
        }
        let Some(value) = percent_byte(bytes, index) else {
            return Err(EndpointError::UnixBadPercentEscape);
        };
        if value == b'/' {
            return Err(EndpointError::UnixEncodedSeparator);
        }
        if value == 0 {
            return Err(EndpointError::UnixEncodedNul);
        }
        decoded.push(value);
        index += 3;
    }
    String::from_utf8(decoded).map_err(|_invalid| EndpointError::UnixPathNotUtf8)
}

fn percent_byte(bytes: &[u8], index: usize) -> Option<u8> {
    let high = hex_value(*bytes.get(index + 1)?)?;
    let low = hex_value(*bytes.get(index + 2)?)?;
    Some((high << 4) | low)
}

const fn hex_value(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::{Endpoint, EndpointError};
    use std::net::IpAddr;
    use std::path::PathBuf;

    #[test]
    fn parse_correct_unix_address_triple_slash() {
        let ep = Endpoint::parse("unix:///foo").unwrap();
        assert_eq!(ep, Endpoint::Unix(PathBuf::from("/foo")));
    }

    #[test]
    fn parse_correct_unix_address_single_slash() {
        let ep = Endpoint::parse("unix:/tmp/spire-agent/public/api.sock").unwrap();
        assert_eq!(
            ep,
            Endpoint::Unix(PathBuf::from("/tmp/spire-agent/public/api.sock"))
        );
    }

    #[test]
    fn parse_correct_tcp_address() {
        let ep = Endpoint::parse("tcp://1.2.3.4:80").unwrap();
        let expected_host: IpAddr = "1.2.3.4".parse().unwrap();

        assert_eq!(
            ep,
            Endpoint::Tcp {
                host: expected_host,
                port: 80
            }
        );
    }

    #[test]
    fn from_str_delegates_to_parse() {
        use std::str::FromStr as _;
        let ep1 = Endpoint::parse("unix:///tmp/sock").unwrap();
        let ep2 = Endpoint::from_str("unix:///tmp/sock").unwrap();
        assert_eq!(ep1, ep2);

        let ep3 = Endpoint::parse("tcp://127.0.0.1:8080").unwrap();
        let ep4 = Endpoint::from_str("tcp://127.0.0.1:8080").unwrap();
        assert_eq!(ep3, ep4);
    }

    #[test]
    fn parse_correct_tcp_address_shorthand() {
        let ep = Endpoint::parse("tcp:127.0.0.1:8081").unwrap();
        let expected_host: IpAddr = "127.0.0.1".parse().unwrap();

        assert_eq!(
            ep,
            Endpoint::Tcp {
                host: expected_host,
                port: 8081
            }
        );
    }

    #[test]
    fn parse_correct_tcp_address_ipv6() {
        let ep = Endpoint::parse("tcp://[::1]:8080").unwrap();
        let expected_host: IpAddr = "::1".parse().unwrap();

        assert_eq!(
            ep,
            Endpoint::Tcp {
                host: expected_host,
                port: 8080
            }
        );
    }

    #[test]
    fn parse_correct_tcp_address_ipv6_shorthand() {
        let ep = Endpoint::parse("tcp:[::1]:8080").unwrap();
        let expected_host: IpAddr = "::1".parse().unwrap();

        assert_eq!(
            ep,
            Endpoint::Tcp {
                host: expected_host,
                port: 8080
            }
        );
    }

    #[test]
    fn parse_errors_are_stable_across_url_versions() {
        for input in [" ", "foo"] {
            let err = Endpoint::parse(input).unwrap_err();
            let EndpointError::Parse(parse_error) = &err else {
                panic!("invalid URI should return an endpoint parse error");
            };

            let displayed = parse_error.to_string();
            assert_ne!(displayed, "");
            assert_ne!(displayed, err.to_string());
            if let Some(cause) = std::error::Error::source(parse_error) {
                assert_ne!(cause.to_string(), displayed);
            }
            assert_eq!(err.to_string(), "endpoint socket is not a valid URI");
        }
    }

    macro_rules! parse_error_tests {
        ($($name:ident: $value:expr_2021,)*) => {
            $(
                #[test]
                fn $name() {
                    let (input, expected_error, expected_message) = $value;

                    let err = Endpoint::parse(input).unwrap_err();

                    assert_eq!(
                        std::mem::discriminant(&err),
                        std::mem::discriminant(&expected_error)
                    );
                    assert_eq!(err.to_string(), expected_message);
                }
            )*
        }
    }

    parse_error_tests! {
        parse_invalid_scheme: (
            "other:///path",
            EndpointError::InvalidScheme,
            "endpoint socket URI scheme must be unix: or tcp:",
        ),

        parse_unix_uri_empty_path: (
            "unix://",
            EndpointError::UnixMissingPath,
            "unix: endpoint socket URI must include a path",
        ),
        parse_unix_uri_empty_path_slash: (
            "unix:///",
            EndpointError::UnixMissingPath,
            "unix: endpoint socket URI must include a path",
        ),
        parse_unix_uri_with_query_values: (
            "unix:///foo?whatever",
            EndpointError::HasQuery,
            "endpoint socket URI must not include query values",
        ),
        parse_unix_uri_with_fragment: (
            "unix:///foo#whatever",
            EndpointError::HasFragment,
            "endpoint socket URI must not include a fragment",
        ),
        parse_unix_uri_with_user_info: (
            "unix://john:doe@foo/path",
            EndpointError::HasUserInfo,
            "endpoint socket URI must not include user info",
        ),
        parse_unix_uri_with_authority: (
            "unix://tmp/spire-agent/public/api.sock",
            EndpointError::UnixAuthorityNotAllowed,
            "unix: endpoint socket URI must not include an authority",
        ),

        parse_tcp_uri_non_empty_path: (
            "tcp://1.2.3.4:80/path",
            EndpointError::TcpUnexpectedPath,
            "tcp: endpoint socket URI must not include a path",
        ),
        parse_tcp_uri_with_query_values: (
            "tcp://1.2.3.4:80?whatever",
            EndpointError::HasQuery,
            "endpoint socket URI must not include query values",
        ),
        parse_tcp_uri_with_fragment: (
            "tcp://1.2.3.4:80#whatever",
            EndpointError::HasFragment,
            "endpoint socket URI must not include a fragment",
        ),
        parse_tcp_uri_with_user_info: (
            "tcp://john:doe@1.2.3.4:80",
            EndpointError::HasUserInfo,
            "endpoint socket URI must not include user info",
        ),
        parse_tcp_uri_with_password_only_user_info: (
            "tcp://:secret@127.0.0.1:8080",
            EndpointError::HasUserInfo,
            "endpoint socket URI must not include user info",
        ),

        parse_tcp_uri_no_ip: (
            "tcp://foo:80",
            EndpointError::TcpHostNotIp,
            "tcp: endpoint socket URI host must be an IP address",
        ),
        parse_tcp_uri_no_port: (
            "tcp://1.2.3.4",
            EndpointError::TcpMissingPort,
            "tcp: endpoint socket URI must include a port",
        ),
    }

    #[test]
    fn parse_unix_missing_slash_after_scheme() {
        // `unix:tmp/sock` (missing slash after scheme) should fail deterministically
        // because the path is not absolute (doesn't start with "/").
        let err = Endpoint::parse("unix:tmp/sock").unwrap_err();
        assert!(matches!(err, EndpointError::UnixMissingPath));
        assert_eq!(
            err.to_string(),
            "unix: endpoint socket URI must include a path"
        );
    }

    #[test]
    fn parse_tcp_with_root_path() {
        // `tcp://127.0.0.1:8080/` should be accepted (path "/")
        let ep = Endpoint::parse("tcp://127.0.0.1:8080/").unwrap();
        let expected_host: IpAddr = "127.0.0.1".parse().unwrap();
        assert_eq!(
            ep,
            Endpoint::Tcp {
                host: expected_host,
                port: 8080
            }
        );
    }

    #[test]
    fn parse_tcp_shorthand_missing_port() {
        // `tcp:127.0.0.1` should return TcpMissingPort
        let err = Endpoint::parse("tcp:127.0.0.1").unwrap_err();
        assert!(matches!(err, EndpointError::TcpMissingPort));
        assert_eq!(
            err.to_string(),
            "tcp: endpoint socket URI must include a port"
        );
    }

    #[test]
    fn parse_tcp_ipv6_missing_port() {
        // `tcp://[::1]` should return TcpMissingPort
        let err = Endpoint::parse("tcp://[::1]").unwrap_err();
        assert!(matches!(err, EndpointError::TcpMissingPort));
        assert_eq!(
            err.to_string(),
            "tcp: endpoint socket URI must include a port"
        );
    }

    #[test]
    fn parse_unix_paths_preserve_decoded_filesystem_names() {
        let cases = [
            (
                "unix:///tmp/spire-agent/public/api.sock",
                "/tmp/spire-agent/public/api.sock",
            ),
            (
                "unix:/tmp/spire-agent/public/api.sock",
                "/tmp/spire-agent/public/api.sock",
            ),
            ("UNIX:///tmp/api.sock", "/tmp/api.sock"),
            ("Unix:/tmp/api.sock", "/tmp/api.sock"),
            ("unix:///tmp/agent%20sock", "/tmp/agent sock"),
            ("unix:///tmp/agent sock", "/tmp/agent sock"),
            ("unix:/tmp/agent%20sock", "/tmp/agent sock"),
            ("UNIX:/tmp/agent sock", "/tmp/agent sock"),
            ("unix:///tmp/agent%25sock", "/tmp/agent%sock"),
            ("unix:///tmp/agent%2520sock", "/tmp/agent%20sock"),
            ("unix:///tmp/%C3%A5gent.sock", "/tmp/\u{e5}gent.sock"),
            ("unix:///tmp/\u{e5}gent.sock", "/tmp/\u{e5}gent.sock"),
            ("unix:///tmp/api%3Fsock", "/tmp/api?sock"),
            ("unix:///tmp/api%23sock", "/tmp/api#sock"),
            (
                "unix:///tmp/missing/../real.sock",
                "/tmp/missing/../real.sock",
            ),
            (
                "unix:///tmp/missing/%2E%2E/real.sock",
                "/tmp/missing/../real.sock",
            ),
            ("unix:///tmp/%2E/real.sock", "/tmp/./real.sock"),
            ("unix:///tmp/foo%2Ebar", "/tmp/foo.bar"),
            ("unix:////tmp/api.sock", "//tmp/api.sock"),
            ("unix:///tmp//api.sock", "/tmp//api.sock"),
            ("unix:///tmp/api.sock/", "/tmp/api.sock/"),
            ("unix:/tmp//api.sock//", "/tmp//api.sock//"),
            ("unix:///tmp/foo\\bar", "/tmp/foo\\bar"),
            ("unix:///tmp/foo%5Cbar", "/tmp/foo\\bar"),
            ("unix:///tmp/foo\"bar", "/tmp/foo\"bar"),
            ("unix:///tmp/foo%22bar", "/tmp/foo\"bar"),
            ("unix:///tmp/foo^bar", "/tmp/foo^bar"),
            ("unix:///tmp/foo%5Ebar", "/tmp/foo^bar"),
            ("unix:///tmp/foo@bar", "/tmp/foo@bar"),
            ("unix:///tmp/foo%40bar", "/tmp/foo@bar"),
            ("unix:///tmp/foo:80/bar", "/tmp/foo:80/bar"),
            ("unix:///tmp/%252Fagent.sock", "/tmp/%2Fagent.sock"),
            ("unix:///tmp/foo%09bar", "/tmp/foo\tbar"),
            ("unix:///tmp/foo%0Abar", "/tmp/foo\nbar"),
            ("unix:///tmp/foo%0Dbar", "/tmp/foo\rbar"),
            ("unix:///tmp/foo%1Fbar", "/tmp/foo\u{1F}bar"),
            ("unix:///tmp/foo%7Fbar", "/tmp/foo\u{7F}bar"),
            ("unix:///tmp/foo%0Bbar", "/tmp/foo\u{0B}bar"),
            ("unix:///tmp/%c3%a5gent.sock", "/tmp/\u{e5}gent.sock"),
            ("unix:///./real.sock", "/./real.sock"),
            ("unix:///./", "/./"),
            ("unix:///.", "/."),
            ("unix:///..", "/.."),
            ("unix:///tmp/foo/..", "/tmp/foo/.."),
            ("unix:///tmp/foo/../", "/tmp/foo/../"),
            ("unix:////", "//"),
            ("unix:///tmp/{foo}", "/tmp/{foo}"),
            ("unix:///tmp/%7Bfoo%7D", "/tmp/{foo}"),
            ("unix:///tmp/foo%60bar", "/tmp/foo`bar"),
            ("unix:///tmp/sock\u{00A0}", "/tmp/sock\u{00A0}"),
        ];

        for (input, expected) in cases {
            let endpoint = Endpoint::parse(input).unwrap_or_else(|error| {
                panic!("{input} should parse, got {error}");
            });
            let Endpoint::Unix(path) = &endpoint else {
                panic!("{input} parsed as {endpoint:?}");
            };
            // `PathBuf` equality compares components, which ignores repeated
            // separators, `.` segments, and a trailing `/`. Compare the exact
            // string passed to `connect`.
            assert_eq!(path.to_str(), Some(expected), "{input}");
        }
    }

    #[test]
    #[expect(
        clippy::too_many_lines,
        reason = "the Unix rejection matrix is one table"
    )]
    fn parse_unix_paths_reject_ambiguous_or_illegal_encodings() {
        let invalid_character = "unix: endpoint socket path contains an invalid character";
        let bad_escape = "unix: endpoint socket path contains a malformed percent escape";
        let encoded_separator =
            "unix: endpoint socket path must not percent-encode a path separator";
        let encoded_nul = "unix: endpoint socket path must not contain a NUL byte";
        let not_utf8 = "unix: endpoint socket path is not valid UTF-8";
        let missing_path = "unix: endpoint socket URI must include a path";
        let authority = "unix: endpoint socket URI must not include an authority";
        let user_info = "endpoint socket URI must not include user info";

        let cases = [
            (
                "unix:///tmp/agent%2Fsock",
                EndpointError::UnixEncodedSeparator,
                encoded_separator,
            ),
            (
                "unix:///tmp/agent%2fsock",
                EndpointError::UnixEncodedSeparator,
                encoded_separator,
            ),
            (
                "unix:///tmp/agent%2F%2Fsock",
                EndpointError::UnixEncodedSeparator,
                encoded_separator,
            ),
            (
                "unix:///%2Ftmp/sock",
                EndpointError::UnixEncodedSeparator,
                encoded_separator,
            ),
            (
                "unix:///tmp/agent%00sock",
                EndpointError::UnixEncodedNul,
                encoded_nul,
            ),
            (
                "unix:///tmp/%00agent.sock",
                EndpointError::UnixEncodedNul,
                encoded_nul,
            ),
            (
                "unix:///tmp/agent%sock",
                EndpointError::UnixBadPercentEscape,
                bad_escape,
            ),
            (
                "unix:///tmp/agent%2",
                EndpointError::UnixBadPercentEscape,
                bad_escape,
            ),
            (
                "unix:///tmp/agent%",
                EndpointError::UnixBadPercentEscape,
                bad_escape,
            ),
            (
                "unix:///tmp/agent%ZZsock",
                EndpointError::UnixBadPercentEscape,
                bad_escape,
            ),
            (
                "unix:///tmp/agent%2Gsock",
                EndpointError::UnixBadPercentEscape,
                bad_escape,
            ),
            (
                "unix:///tmp/agent%2gsock",
                EndpointError::UnixBadPercentEscape,
                bad_escape,
            ),
            (
                "unix:///tmp/%%20sock",
                EndpointError::UnixBadPercentEscape,
                bad_escape,
            ),
            (
                "unix:///tmp/agent%20%",
                EndpointError::UnixBadPercentEscape,
                bad_escape,
            ),
            (
                "unix:///tmp/%FFgent.sock",
                EndpointError::UnixPathNotUtf8,
                not_utf8,
            ),
            (
                "unix:///tmp/%80gent.sock",
                EndpointError::UnixPathNotUtf8,
                not_utf8,
            ),
            (
                "unix:///tmp/%C3gent.sock",
                EndpointError::UnixPathNotUtf8,
                not_utf8,
            ),
            (
                "unix:///tmp/%C3%28gent.sock",
                EndpointError::UnixPathNotUtf8,
                not_utf8,
            ),
            (
                "unix:///tmp/%C0%AFgent.sock",
                EndpointError::UnixPathNotUtf8,
                not_utf8,
            ),
            (
                "unix:///tmp/%C0%80gent.sock",
                EndpointError::UnixPathNotUtf8,
                not_utf8,
            ),
            (
                "unix:///tmp/\u{e5}%FFgent.sock",
                EndpointError::UnixPathNotUtf8,
                not_utf8,
            ),
            (
                "unix:///tmp/api\tsock",
                EndpointError::UnixInvalidCharacter,
                invalid_character,
            ),
            (
                "unix:///tmp/api\nsock",
                EndpointError::UnixInvalidCharacter,
                invalid_character,
            ),
            (
                "unix:///tmp/api\rsock",
                EndpointError::UnixInvalidCharacter,
                invalid_character,
            ),
            (
                "unix:///tmp/api\u{000B}sock",
                EndpointError::UnixInvalidCharacter,
                invalid_character,
            ),
            (
                "unix:///tmp/api\u{007F}sock",
                EndpointError::UnixInvalidCharacter,
                invalid_character,
            ),
            (
                "unix:///tmp/a\0b",
                EndpointError::UnixInvalidCharacter,
                invalid_character,
            ),
            (
                "uni\tx:///tmp/api.sock",
                EndpointError::UnixInvalidCharacter,
                invalid_character,
            ),
            (
                "unix:/\t//tmp/api.sock",
                EndpointError::UnixInvalidCharacter,
                invalid_character,
            ),
            (
                "unix:///\ttmp/api.sock",
                EndpointError::UnixInvalidCharacter,
                invalid_character,
            ),
            (
                "unix://\t/tmp/api.sock",
                EndpointError::UnixInvalidCharacter,
                invalid_character,
            ),
            (
                " unix:///tmp/api.sock",
                EndpointError::UnixInvalidCharacter,
                invalid_character,
            ),
            (
                "unix:///tmp/api.sock ",
                EndpointError::UnixInvalidCharacter,
                invalid_character,
            ),
            (
                "unix:///tmp/api.sock\t",
                EndpointError::UnixInvalidCharacter,
                invalid_character,
            ),
            (
                "  unix:///tmp/api.sock  ",
                EndpointError::UnixInvalidCharacter,
                invalid_character,
            ),
            (
                "unix:%2Ftmp/sock",
                EndpointError::UnixMissingPath,
                missing_path,
            ),
            (
                "unix://%2e%2e/tmp/sock",
                EndpointError::UnixAuthorityNotAllowed,
                authority,
            ),
            (
                "unix://foo%40bar/tmp",
                EndpointError::UnixAuthorityNotAllowed,
                authority,
            ),
            (
                "unix://tmp/sock\t",
                EndpointError::UnixAuthorityNotAllowed,
                authority,
            ),
            (
                "unix://tm\tp/sock",
                EndpointError::UnixAuthorityNotAllowed,
                authority,
            ),
            // `Url` drops empty user info and reports no host for these.
            (
                "unix://:@/tmp/api.sock",
                EndpointError::HasUserInfo,
                user_info,
            ),
            (
                "Unix://:@/tmp/api.sock",
                EndpointError::HasUserInfo,
                user_info,
            ),
            ("unix://@", EndpointError::HasUserInfo, user_info),
            ("unix://:@", EndpointError::HasUserInfo, user_info),
        ];

        for (input, expected, message) in cases {
            let err = match Endpoint::parse(input) {
                Ok(endpoint) => panic!("{input} parsed as {endpoint:?}"),
                Err(err) => err,
            };
            assert_eq!(
                std::mem::discriminant(&err),
                std::mem::discriminant(&expected),
                "{input}: {err:?}"
            );
            assert_eq!(err.to_string(), message, "{input}");
        }

        for input in [
            "unix:// /tmp/sock",
            "\u{00A0}unix:///tmp/sock",
            "unix://foo\\bar/baz",
            "unix://@/tmp/sock",
            "unix://user@/tmp/sock",
            "unix://user:pass@/tmp/sock",
        ] {
            let err = match Endpoint::parse(input) {
                Ok(endpoint) => panic!("{input} parsed as {endpoint:?}"),
                Err(err) => err,
            };
            assert!(matches!(err, EndpointError::Parse(_)), "{input}: {err:?}");
            assert_eq!(err.to_string(), "endpoint socket is not a valid URI");
        }
    }

    #[test]
    fn parse_tcp_endpoint_behavior_is_unchanged() {
        let ep = Endpoint::parse("tcp://127.0.0.1:8080 ").unwrap();
        assert_eq!(
            ep,
            Endpoint::Tcp {
                host: "127.0.0.1".parse().unwrap(),
                port: 8080
            }
        );

        let ep = Endpoint::parse("tcp://127.0.0.1:8080\t").unwrap();
        assert_eq!(
            ep,
            Endpoint::Tcp {
                host: "127.0.0.1".parse().unwrap(),
                port: 8080
            }
        );

        let ep = Endpoint::parse("Tcp://[::1]:8080").unwrap();
        assert_eq!(
            ep,
            Endpoint::Tcp {
                host: "::1".parse().unwrap(),
                port: 8080
            }
        );

        let err = Endpoint::parse("tcp://127%2e0%2e0%2e1:8080").unwrap_err();
        assert!(matches!(err, EndpointError::TcpHostNotIp));

        let err = Endpoint::parse("TCP:127.0.0.1:8080").unwrap_err();
        assert!(matches!(err, EndpointError::TcpHostNotIp));
    }

    #[cfg(unix)]
    #[test]
    fn percent_encoded_and_literal_space_connect_to_the_decoded_socket() {
        use std::io::ErrorKind;
        use std::os::unix::net::{UnixListener, UnixStream};

        let dir = PathBuf::from(format!(
            "/tmp/spiffe-f02-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("clock")
                .as_nanos()
        ));
        std::fs::create_dir(&dir).expect("temp dir");
        let _cleanup = DirCleanup(dir.clone());

        let space_path = dir.join("agent sock");
        let encoded_path = dir.join("agent%20sock");
        let space_listener = UnixListener::bind(&space_path).expect("bind space socket");
        let encoded_listener = UnixListener::bind(&encoded_path).expect("bind encoded socket");
        space_listener
            .set_nonblocking(true)
            .expect("space nonblocking");
        encoded_listener
            .set_nonblocking(true)
            .expect("encoded nonblocking");

        let space_uri = format!("unix://{}", space_path.display());
        let encoded_uri = format!("unix://{}", encoded_path.display());

        for uri in [&space_uri, &encoded_uri] {
            let endpoint = Endpoint::parse(uri).unwrap_or_else(|error| panic!("{uri}: {error}"));
            let Endpoint::Unix(path) = &endpoint else {
                panic!("{uri} parsed as {endpoint:?}");
            };
            assert_eq!(path, &space_path, "{uri}");
            let client = UnixStream::connect(path).unwrap_or_else(|error| {
                panic!("{uri} parsed as {path:?} and connect failed: {error}");
            });
            drop(client);

            let space_hit = match space_listener.accept() {
                Ok(_) => true,
                Err(error) if error.kind() == ErrorKind::WouldBlock => false,
                Err(error) => panic!("space accept: {error}"),
            };
            let encoded_hit = match encoded_listener.accept() {
                Ok(_) => true,
                Err(error) if error.kind() == ErrorKind::WouldBlock => false,
                Err(error) => panic!("encoded accept: {error}"),
            };
            assert!(
                space_hit && !encoded_hit,
                "{uri} parsed as {path:?}; space={space_hit} encoded={encoded_hit}"
            );
        }
    }

    #[cfg(unix)]
    struct DirCleanup(PathBuf);

    #[cfg(unix)]
    impl Drop for DirCleanup {
        fn drop(&mut self) {
            drop(std::fs::remove_dir_all(&self.0));
        }
    }
}
