//! Workload API endpoint handling.
//!
//! SPIFFE Workload API clients discover the endpoint via the
//! `SPIFFE_ENDPOINT_SOCKET` environment variable.
//!
//! Wires that environment variable to the shared [`Endpoint`] parser.

use crate::transport::Endpoint;
use crate::workload_api::error::WorkloadApiError;

/// Environment variable holding the Workload API endpoint.
pub const WORKLOAD_API_ENDPOINT_ENV: &str = "SPIFFE_ENDPOINT_SOCKET";

/// Load and parse the Workload API endpoint from `SPIFFE_ENDPOINT_SOCKET`.
///
/// The value is parsed with [`Endpoint::parse`](crate::transport::Endpoint::parse),
/// including Unix percent-decoding. It is not a separate path grammar.
///
/// ## Errors
///
/// Returns a [`WorkloadApiError`] if:
/// - the `SPIFFE_ENDPOINT_SOCKET` environment variable is not set, or
/// - the value of `SPIFFE_ENDPOINT_SOCKET` is not a valid SPIFFE endpoint URI.
pub fn from_env() -> Result<Endpoint, WorkloadApiError> {
    let raw = std::env::var_os(WORKLOAD_API_ENDPOINT_ENV)
        .ok_or(WorkloadApiError::MissingEndpointSocket)?;
    if let Some(raw) = raw.to_str() {
        Ok(Endpoint::parse(raw)?)
    } else {
        Err(WorkloadApiError::NotUnicodeEndpointSocket(raw))
    }
}

#[cfg(test)]
mod tests {
    use super::{from_env, WORKLOAD_API_ENDPOINT_ENV};
    use crate::transport::Endpoint;
    use std::path::PathBuf;
    use std::process::Command;

    /// Marks the child process that makes the environment assertions.
    const CHILD_ENV: &str = "RUST_SPIFFE_TEST_ENDPOINT_ENV_CHILD";

    #[test]
    fn from_env_matches_parse_for_percent_encoded_unix_path() {
        let value = "unix:///tmp/agent%20sock";

        if std::env::var_os(CHILD_ENV).is_some() {
            let endpoint = from_env().expect("encoded unix endpoint");
            assert_eq!(endpoint, Endpoint::parse(value).expect("parse"));
            assert_eq!(endpoint, Endpoint::Unix(PathBuf::from("/tmp/agent sock")));
            return;
        }

        // Changing this process's environment is unsound while other test threads
        // run, so rerun only this test in a child that starts with the variable set.
        let (_, module) = module_path!().split_once("::").expect("crate prefix");
        let test = format!("{module}::from_env_matches_parse_for_percent_encoded_unix_path");
        let output = Command::new(std::env::current_exe().expect("test binary path"))
            .args([test.as_str(), "--exact"])
            .env(CHILD_ENV, "1")
            .env(WORKLOAD_API_ENDPOINT_ENV, value)
            .output()
            .expect("run child test process");
        let stdout = String::from_utf8_lossy(&output.stdout);
        // A filter that matches nothing also exits successfully.
        assert!(
            output.status.success() && stdout.contains("1 passed"),
            "child test failed ({}):\n{stdout}\n{}",
            output.status,
            String::from_utf8_lossy(&output.stderr)
        );
    }
}
