//! Provides functions to validate SPIFFE socket endpoint paths.

use std::env;
use std::net::IpAddr;
use std::str::FromStr;

use thiserror::Error;
use url::{ParseError, Url};

/// Name of the environment variable that holds the default socket endpoint path.
pub const SOCKET_ENV: &str = "SPIFFE_ENDPOINT_SOCKET";

const TCP_SCHEME: &str = "tcp";
const UNIX_SCHEME: &str = "unix";

/// Gets the endpoint socket endpoint path from the environment variable `SPIFFE_ENDPOINT_SOCKET`,
/// as described in [SPIFFE standard](https://github.com/spiffe/spiffe/blob/main/standards/SPIFFE_Workload_Endpoint.md#4-locating-the-endpoint).
pub fn get_default_socket_path() -> Option<String> {
    match env::var(SOCKET_ENV) {
        Ok(addr) => Some(String::from(addr.strip_prefix("unix:").unwrap())),
        Err(_) => None,
    }
}

/// An error that arises validating a SPIFFE endpoint socket path.
#[derive(Debug, Error, PartialEq, Copy, Clone)]
#[non_exhaustive]
pub enum SocketPathError {
    /// The SPIFFE endpoint socket URI has a scheme other than 'unix' or 'tcp'.
    #[error("workload endpoint socket URI must have a tcp:// or unix:// scheme")]
    InvalidScheme,

    /// The SPIFFE endpoint unix socket URI does not include a path.
    #[error("workload endpoint unix socket URI must include a path")]
    UnixAddressEmptyPath,

    /// The SPIFFE endpoint tcp socket URI include a path.
    #[error("workload endpoint tcp socket URI must not include a path")]
    TcpAddressNonEmptyPath,

    /// The SPIFFE endpoint socket URI has query values.
    #[error("workload endpoint socket URI must not include query values")]
    HasQueryValues,

    /// The SPIFFE endpoint socket URI has a fragment.
    #[error("workload endpoint socket URI must not include a fragment")]
    HasFragment,

    /// The SPIFFE endpoint socket URI has query user info.
    #[error("workload endpoint socket URI must not include user info")]
    HasUserInfo,

    /// The SPIFFE endpoint tcp socket URI has misses a host.
    #[error("workload endpoint tcp socket URI must include a host")]
    TcpEmptyHost,

    /// The SPIFFE endpoint tcp socket URI has misses a port.
    #[error("workload endpoint tcp socket URI host component must be an IP:port")]
    TcpAddressNoIpPort,

    /// Error returned by the URI parsing library.
    #[error("workload endpoint socket is not a valid URI")]
    Parse(#[from] ParseError),
}

/// Validates that the `socket_path` complies with [SPIFFE standard](https://github.com/spiffe/spiffe/blob/main/standards/SPIFFE_Workload_Endpoint.md#4-locating-the-endpoint).
pub fn validate_socket_path(socket_path: &str) -> Result<(), SocketPathError> {
    let url = Url::parse(socket_path)?;

    if !url.username().is_empty() {
        return Err(SocketPathError::HasUserInfo);
    }

    if url.query().is_some() {
        return Err(SocketPathError::HasQueryValues);
    }

    if url.fragment().is_some() {
        return Err(SocketPathError::HasFragment);
    }

    match url.scheme() {
        UNIX_SCHEME => {
            if url.path().is_empty() || url.path() == "/" {
                return Err(SocketPathError::UnixAddressEmptyPath);
            }
        }
        TCP_SCHEME => {
            let host = match url.host_str() {
                None => return Err(SocketPathError::TcpEmptyHost),
                Some(h) => h,
            };

            let ip_address = IpAddr::from_str(host);
            if ip_address.is_err() {
                return Err(SocketPathError::TcpAddressNoIpPort);
            }

            if !url.path().is_empty() && url.path() != "/" {
                return Err(SocketPathError::TcpAddressNonEmptyPath);
            }
            if url.port().is_none() {
                return Err(SocketPathError::TcpAddressNoIpPort);
            }
        }
        _ => return Err(SocketPathError::InvalidScheme),
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_validate_correct_unix_address() {
        let socket_path = "unix:///foo";
        validate_socket_path(socket_path).unwrap();
    }

    #[test]
    fn test_validate_other_correct_unix_address() {
        let socket_path = "unix:/tmp/spire-agent/public/api.sock";
        validate_socket_path(socket_path).unwrap();
    }

    #[test]
    fn test_validate_correct_tcp_address() {
        let socket_path = "tcp://1.2.3.4:80";
        validate_socket_path(socket_path).unwrap();
    }

    macro_rules! validate_socket_path_error_tests {
        ($($name:ident: $value:expr,)*) => {
        $(
            #[test]
            fn $name() {
                let (input, expected_error, expected_message) = $value;
                let result = validate_socket_path(input);
                let error = result.unwrap_err();

                assert_eq!(error, expected_error);
                assert_eq!(error.to_string(), expected_message);
            }
        )*
        }
    }

    validate_socket_path_error_tests! {
        test_validate_empty_str: (" ", SocketPathError::Parse(ParseError::RelativeUrlWithoutBase), "workload endpoint socket is not a valid URI"),
        test_validate_str_missing_scheme: ("foo", SocketPathError::Parse(ParseError::RelativeUrlWithoutBase), "workload endpoint socket is not a valid URI"),
        test_validate_uri_invalid_scheme: ("other:///path", SocketPathError::InvalidScheme, "workload endpoint socket URI must have a tcp:// or unix:// scheme"),

        test_validate_unix_uri_empty_path: ("unix://", SocketPathError::UnixAddressEmptyPath, "workload endpoint unix socket URI must include a path"),
        test_validate_unix_uri_empty_path_slash: ("unix:///", SocketPathError::UnixAddressEmptyPath, "workload endpoint unix socket URI must include a path"),
        test_validate_unix_uri_with_query_values: ("unix:///foo?whatever", SocketPathError::HasQueryValues, "workload endpoint socket URI must not include query values"),
        test_validate_unix_uri_with_fragment: ("unix:///foo#whatever", SocketPathError::HasFragment, "workload endpoint socket URI must not include a fragment"),
        test_validate_unix_uri_with_user_info: ("unix://john:doe@foo/path", SocketPathError::HasUserInfo, "workload endpoint socket URI must not include user info"),

        test_validate_tcp_uri_non_empty_path: ("tcp://1.2.3.4:80/path", SocketPathError::TcpAddressNonEmptyPath, "workload endpoint tcp socket URI must not include a path"),
        test_validate_tcp_uri_with_query_values: ("tcp://1.2.3.4:80?whatever", SocketPathError::HasQueryValues, "workload endpoint socket URI must not include query values"),
        test_validate_tcp_uri_with_fragment: ("tcp://1.2.3.4:80#whatever", SocketPathError::HasFragment, "workload endpoint socket URI must not include a fragment"),
        test_validate_tcp_uri_with_user_info: ("tcp://john:doe@1.2.3.4:80", SocketPathError::HasUserInfo, "workload endpoint socket URI must not include user info"),
        test_validate_tcp_uri_no_ip: ("tcp://foo:80", SocketPathError::TcpAddressNoIpPort, "workload endpoint tcp socket URI host component must be an IP:port"),
        test_validate_tcp_uri_no_ip_and_port: ("tcp://foo", SocketPathError::TcpAddressNoIpPort, "workload endpoint tcp socket URI host component must be an IP:port"),
        test_validate_tcp_uri_no_port: ("tcp://1.2.3.4", SocketPathError::TcpAddressNoIpPort, "workload endpoint tcp socket URI host component must be an IP:port"),
    }
}
