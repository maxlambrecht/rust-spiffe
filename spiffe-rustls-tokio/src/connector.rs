//! TLS connector for client-side connections.

use crate::error::Error;
use crate::identity::{extract_peer_identity_from_client, PeerIdentity};
use rustls::pki_types::ServerName;
use rustls::ClientConfig;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::TcpStream;
use tokio_rustls::client::TlsStream;
use tokio_rustls::TlsConnector as TokioTlsConnector;

/// A TLS connector that extracts peer SPIFFE identity from established connections.
///
/// This is a wrapper around [`tokio_rustls::TlsConnector`] that automatically extracts
/// the peer's SPIFFE ID from their certificate after a successful TLS handshake.
///
/// # Example
///
/// ```no_run
/// # use spiffe::X509Source;
/// # use spiffe_rustls::{authorizer, mtls_client};
/// # use spiffe_rustls_tokio::TlsConnector;
/// # use std::sync::Arc;
/// # use tokio::net::TcpStream;
///
/// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
/// let source = X509Source::new().await?;
/// let client_config = mtls_client(source)
///     .authorize(authorizer::any())
///     .build()?;
///
/// let connector = TlsConnector::new(Arc::new(client_config));
/// let stream = TcpStream::connect("127.0.0.1:8443").await?;
///
/// let server_name = rustls::pki_types::ServerName::try_from("example.org")?;
/// match connector.connect(server_name, stream).await {
///     Ok((tls_stream, peer_identity)) => {
///         if let Some(spiffe_id) = peer_identity.spiffe_id() {
///             println!("Connected to server: {}", spiffe_id);
///         }
///         // Use tls_stream...
///     }
///     Err(e) => eprintln!("TLS connection failed: {}", e),
/// }
/// # Ok(())
/// # }
/// ```
#[derive(Clone)]
pub struct TlsConnector {
    inner: TokioTlsConnector,
}

impl std::fmt::Debug for TlsConnector {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TlsConnector").finish_non_exhaustive()
    }
}

impl TlsConnector {
    /// Creates a new `TlsConnector` from a `ClientConfig`.
    pub fn new(config: Arc<ClientConfig>) -> Self {
        Self::from(config)
    }

    /// Establishes a TLS connection to the server over the given TCP stream.
    ///
    /// After a successful TLS handshake, the peer's SPIFFE ID is extracted from
    /// their certificate and returned along with the TLS stream.
    ///
    /// # Arguments
    ///
    /// * `server_name` - The server name to use for SNI (Server Name Indication).
    ///   Note: With SPIFFE, authentication is based on SPIFFE ID, not hostname.
    ///   The `ServerName` is required by rustls for the TLS protocol (SNI).
    /// * `stream` - The TCP stream to wrap with TLS.
    ///
    /// # SPIFFE X.509-SVID Expectations
    ///
    /// According to the SPIFFE specification, an X.509-SVID must contain **exactly one** SPIFFE ID
    /// in the URI SAN, and peers are expected to present certificates when mTLS is required.
    /// When using `spiffe-rustls` verifiers correctly, these requirements are enforced during
    /// the TLS handshake, and cases where `peer_identity.spiffe_id` is `None` should normally
    /// be unreachable.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The TLS handshake fails (`Error::Rustls`)
    /// - The peer certificate cannot be parsed after a successful handshake (`Error::CertParse`)
    ///
    /// If identity extraction fails after a successful handshake, `connect()` returns
    /// an error and the connection is closed. If the peer certificate doesn't contain
    /// a SPIFFE ID, contains multiple SPIFFE IDs, or no peer certificates are present,
    /// `connect()` succeeds and `peer_identity.spiffe_id` will be `None`.
    ///
    /// **Note**: A `None` value for `spiffe_id` is unexpected in SPIFFE-compliant configurations
    /// and may indicate that the TLS configuration is not enforcing SPIFFE semantics, or that
    /// the peer is not presenting a valid SPIFFE X.509-SVID.
    pub async fn connect(
        &self,
        server_name: ServerName<'static>,
        stream: TcpStream,
    ) -> Result<(TlsStream<TcpStream>, PeerIdentity), Error> {
        let tls_stream = self.inner.connect(server_name, stream).await?;

        // Extract peer identity from the verified connection
        let (_io, client_conn) = tls_stream.get_ref();
        let peer_identity = extract_peer_identity_from_client(client_conn)?;

        Ok((tls_stream, peer_identity))
    }

    /// Establishes a TCP connection and then performs a TLS handshake.
    ///
    /// Combines `TcpStream::connect` with `connect`.
    ///
    /// # Arguments
    ///
    /// * `addr` - The socket address to connect to.
    /// * `server_name` - The server name to use for SNI (Server Name Indication).
    ///
    /// # SPIFFE X.509-SVID Expectations
    ///
    /// According to the SPIFFE specification, an X.509-SVID must contain **exactly one** SPIFFE ID
    /// in the URI SAN, and peers are expected to present certificates when mTLS is required.
    /// When using `spiffe-rustls` verifiers correctly, these requirements are enforced during
    /// the TLS handshake, and cases where `peer_identity.spiffe_id` is `None` should normally
    /// be unreachable.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The TCP connection fails (`Error::Io`)
    /// - The TLS handshake fails (`Error::Rustls`)
    /// - The peer certificate cannot be parsed after a successful handshake (`Error::CertParse`)
    ///
    /// If identity extraction fails after a successful handshake, `connect_addr()` returns
    /// an error and the connection is closed. If the peer certificate doesn't contain
    /// a SPIFFE ID, contains multiple SPIFFE IDs, or no peer certificates are present,
    /// `connect_addr()` succeeds and `peer_identity.spiffe_id` will be `None`.
    ///
    /// **Note**: A `None` value for `spiffe_id` is unexpected in SPIFFE-compliant configurations
    /// and may indicate that the TLS configuration is not enforcing SPIFFE semantics, or that
    /// the peer is not presenting a valid SPIFFE X.509-SVID.
    pub async fn connect_addr(
        &self,
        addr: SocketAddr,
        server_name: ServerName<'static>,
    ) -> Result<(TlsStream<TcpStream>, PeerIdentity), Error> {
        let stream = TcpStream::connect(addr).await?;
        self.connect(server_name, stream).await
    }
}

impl From<Arc<ClientConfig>> for TlsConnector {
    fn from(config: Arc<ClientConfig>) -> Self {
        Self {
            inner: TokioTlsConnector::from(config),
        }
    }
}
