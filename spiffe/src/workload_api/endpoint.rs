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
#[expect(
    unsafe_code,
    reason = "the test sets SPIFFE_ENDPOINT_SOCKET and restores it before releasing the lock"
)]
mod tests {
    use super::{from_env, WORKLOAD_API_ENDPOINT_ENV};
    use crate::transport::Endpoint;
    use std::path::PathBuf;
    use std::sync::Mutex;

    static ENDPOINT_ENV_LOCK: Mutex<()> = Mutex::new(());

    #[test]
    fn from_env_matches_parse_for_percent_encoded_unix_path() {
        let _lock = ENDPOINT_ENV_LOCK.lock().expect("endpoint env lock");
        let value = "unix:///tmp/agent%20sock";
        // SAFETY: `set_var` is unsafe because another thread can read the environment
        // at the same time. This test is the only writer of `SPIFFE_ENDPOINT_SOCKET`,
        // holds `ENDPOINT_ENV_LOCK` across the read, does not spawn threads, and
        // removes the variable before the lock is released.
        unsafe {
            std::env::set_var(WORKLOAD_API_ENDPOINT_ENV, value);
        }
        let _restore = EnvRestore(WORKLOAD_API_ENDPOINT_ENV);

        let endpoint = from_env().expect("encoded unix endpoint");
        assert_eq!(endpoint, Endpoint::parse(value).expect("parse"));
        assert_eq!(endpoint, Endpoint::Unix(PathBuf::from("/tmp/agent sock")));
    }

    struct EnvRestore(&'static str);

    impl Drop for EnvRestore {
        fn drop(&mut self) {
            // SAFETY: paired with the `set_var` in the test above, which still
            // holds `ENDPOINT_ENV_LOCK` while this guard drops.
            unsafe {
                std::env::remove_var(self.0);
            }
        }
    }
}
