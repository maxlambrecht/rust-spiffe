//! gRPC channel connector for SPIFFE endpoints.
//!
//! Builds a `tonic::transport::Channel` from a parsed [`Endpoint`].
//!
//! Supported transports:
//! - `unix:///path` or `unix:/path` (Unix domain sockets; Unix platforms only)
//! - `tcp://1.2.3.4:port` or `tcp:1.2.3.4:port`
//!
//! Available when the `transport-grpc` feature is enabled (or any feature that enables it,
//! such as `workload-api`).

use std::net::IpAddr;
use std::path::Path;

use hyper_util::rt::TokioIo;
#[cfg(unix)]
use tokio::net::UnixStream;
use tonic::transport::{Channel, Endpoint as TonicEndpoint, Uri};
use tower::service_fn;

use crate::transport::endpoint::Endpoint;
use crate::transport::TransportError;

const TONIC_DUMMY_URI: &str = "http://localhost";

/// Connect to a SPIFFE endpoint and return a `tonic` gRPC channel.
///
/// ## Errors
///
/// Returns [`TransportError`] if:
/// - the endpoint transport is unsupported on the current platform,
/// - the tonic endpoint could not be constructed,
/// - or the underlying connection fails.
pub async fn connect(endpoint: &Endpoint) -> Result<Channel, TransportError> {
    match endpoint {
        Endpoint::Unix(path) => connect_unix(path).await,
        Endpoint::Tcp { host, port } => connect_tcp(*host, *port).await,
    }
}

async fn connect_tcp(host: IpAddr, port: u16) -> Result<Channel, TransportError> {
    let uri = format!("http://{host}:{port}");
    Ok(TonicEndpoint::try_from(uri)?.connect().await?)
}

async fn connect_unix(path: &Path) -> Result<Channel, TransportError> {
    #[cfg(not(unix))]
    {
        let _ = path;
        return Err(TransportError::UnsupportedEndpointTransport { scheme: "unix" });
    }

    #[cfg(unix)]
    {
        let path = path.to_owned();

        let channel = TonicEndpoint::try_from(TONIC_DUMMY_URI)?
            .connect_with_connector(service_fn(move |_: Uri| {
                let path = path.clone();
                async move {
                    let stream = UnixStream::connect(&path).await?;
                    Ok::<_, std::io::Error>(TokioIo::new(stream))
                }
            }))
            .await?;

        Ok(channel)
    }
}
