//! gRPC channel connector for SPIFFE endpoints.
//!
//! This module builds a `tonic::transport::Channel` from a parsed [`Endpoint`].
//!
//! Supported transports:
//! - `unix:///path` (Unix domain sockets; Unix platforms only)
//! - `tcp://1.2.3.4:port`

use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use hyper_util::rt::TokioIo;
#[cfg(unix)]
use tokio::net::UnixStream;
use tonic::transport::{Channel, Endpoint as TonicEndpoint, Uri};
use tower::service_fn;

use crate::endpoint::Endpoint;
use crate::transport::TransportError;

const TONIC_DUMMY_URI: &str = "http://[::]:50051";

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
        let path: Arc<PathBuf> = Arc::new(path.to_path_buf());

        let channel = TonicEndpoint::try_from(TONIC_DUMMY_URI)?
            .connect_with_connector(service_fn(move |_: Uri| {
                let path = Arc::clone(&path);
                async move {
                    let stream = UnixStream::connect(path.as_path()).await?;
                    Ok::<_, std::io::Error>(TokioIo::new(stream))
                }
            }))
            .await?;

        Ok(channel)
    }
}
