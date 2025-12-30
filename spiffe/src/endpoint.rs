//! SPIFFE endpoint parsing and validation.
//!
//! This module defines a SPIFFE-specific endpoint abstraction used by
//! SPIFFE-related APIs such as:
//! - SPIFFE Workload API
//! - SPIRE Agent Admin API
//!
//! It is **not** a general-purpose networking endpoint.

use std::net::IpAddr;
use std::path::PathBuf;
use std::str::FromStr;

use thiserror::Error;
use url::Url;

const TCP_SCHEME: &str = "tcp";
const UNIX_SCHEME: &str = "unix";

/// Parsed SPIFFE endpoint.
#[derive(Debug, Clone, PartialEq, Eq)]
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

/// Errors returned by [`Endpoint::parse`].
#[derive(Debug, Error, PartialEq, Eq)]
pub enum EndpointError {
    /// The input could not be parsed as a valid URI.
    #[error("endpoint socket is not a valid URI")]
    Parse(#[from] url::ParseError),

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
}

impl Endpoint {
    /// Parse and validate a SPIFFE endpoint URI.
    ///
    /// ## Accepted formats
    ///
    /// - `unix:///path/to/socket`
    /// - `unix:/path/to/socket` (accepted in practice)
    /// - `tcp://1.2.3.4:8081`
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
        let url = Url::parse(&normalized)?;

        if !url.username().is_empty() {
            return Err(EndpointError::HasUserInfo);
        }
        if url.query().is_some() {
            return Err(EndpointError::HasQuery);
        }
        if url.fragment().is_some() {
            return Err(EndpointError::HasFragment);
        }

        match url.scheme() {
            UNIX_SCHEME => {
                if url.host_str().is_some() {
                    return Err(EndpointError::UnixAuthorityNotAllowed);
                }

                let path = url.path();
                if path.is_empty() || path == "/" {
                    return Err(EndpointError::UnixMissingPath);
                }

                Ok(Endpoint::Unix(PathBuf::from(path)))
            }

            TCP_SCHEME => {
                let host_str = url.host_str().ok_or(EndpointError::TcpHostNotIp)?;
                let host = IpAddr::from_str(host_str).map_err(|_| EndpointError::TcpHostNotIp)?;
                let port = url.port().ok_or(EndpointError::TcpMissingPort)?;

                let path = url.path();
                if !path.is_empty() && path != "/" {
                    return Err(EndpointError::TcpUnexpectedPath);
                }

                Ok(Endpoint::Tcp { host, port })
            }

            _ => Err(EndpointError::InvalidScheme),
        }
    }
}

fn normalize_endpoint_uri(input: &str) -> String {
    // Accept the shorthand `unix:/path` by rewriting it into a valid URL.
    if input.starts_with("unix:/") && !input.starts_with("unix://") {
        let path = &input["unix:/".len()..];
        return format!("unix:///{path}");
    }

    input.to_owned()
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
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
    fn parse_errors_are_stable_across_url_versions() {
        for input in [" ", "foo"] {
            let err = Endpoint::parse(input).unwrap_err();
            assert!(matches!(err, EndpointError::Parse(_)));
            assert_eq!(err.to_string(), "endpoint socket is not a valid URI");
        }
    }

    macro_rules! parse_error_tests {
        ($($name:ident: $value:expr,)*) => {
            $(
                #[test]
                fn $name() {
                    let (input, expected_error, expected_message) = $value;

                    let err = Endpoint::parse(input).unwrap_err();

                    assert_eq!(err, expected_error);
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
}
