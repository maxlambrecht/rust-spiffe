//! TLS acceptor for server-side connections.

use crate::error::Error;
use crate::identity::{extract_peer_identity_from_server, PeerIdentity};
use rustls::ServerConfig;
use std::sync::Arc;
use tokio::net::TcpStream;
use tokio_rustls::server::TlsStream;
use tokio_rustls::TlsAcceptor as TokioTlsAcceptor;

/// A TLS acceptor that extracts peer SPIFFE identity from accepted connections.
///
/// Wrapper around [`tokio_rustls::TlsAcceptor`] that automatically extracts
/// the peer's SPIFFE ID from their certificate after a successful TLS handshake.
///
/// # Example
///
/// ```no_run
/// # use spiffe::X509Source;
/// # use spiffe_rustls::{authorizer, mtls_server};
/// # use spiffe_rustls_tokio::TlsAcceptor;
/// # use std::sync::Arc;
/// # use tokio::net::TcpListener;
///
/// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
/// let source = X509Source::new().await?;
/// let server_config = mtls_server(source)
///     .authorize(authorizer::any())
///     .build()?;
///
/// let acceptor = TlsAcceptor::new(Arc::new(server_config));
/// let listener = TcpListener::bind("127.0.0.1:8443").await?;
///
/// loop {
///     let (stream, _) = listener.accept().await?;
///     let acceptor = acceptor.clone();
///
///     tokio::spawn(async move {
///         match acceptor.accept(stream).await {
///             Ok((tls_stream, peer_identity)) => {
///                 if let Some(spiffe_id) = peer_identity.spiffe_id() {
///                     println!("Connected peer: {}", spiffe_id);
///                 }
///                 // Use tls_stream...
///             }
///             Err(e) => eprintln!("TLS connection failed: {}", e),
///         }
///     });
/// }
/// # Ok(())
/// # }
/// ```
#[derive(Clone)]
pub struct TlsAcceptor {
    inner: TokioTlsAcceptor,
}

impl std::fmt::Debug for TlsAcceptor {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TlsAcceptor").finish_non_exhaustive()
    }
}

impl TlsAcceptor {
    /// Creates a new `TlsAcceptor` from a `ServerConfig`.
    pub fn new(config: Arc<ServerConfig>) -> Self {
        Self::from(config)
    }

    /// Accepts a TLS connection from the given TCP stream.
    ///
    /// After a successful TLS handshake, the peer's SPIFFE ID is extracted from
    /// their certificate and returned along with the TLS stream.
    ///
    /// See [`PeerIdentity`] for post-handshake extraction outcomes.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The TLS handshake fails (`Error::Rustls`)
    /// - Peer identity extraction fails after a successful handshake ([`Error::CertParse`]).
    pub async fn accept(
        &self,
        stream: TcpStream,
    ) -> Result<(TlsStream<TcpStream>, PeerIdentity), Error> {
        let tls_stream = self.inner.accept(stream).await?;

        // Extract peer identity from the verified connection
        let (_io, server_conn) = tls_stream.get_ref();
        let peer_identity = extract_peer_identity_from_server(server_conn)?;

        Ok((tls_stream, peer_identity))
    }
}

impl From<Arc<ServerConfig>> for TlsAcceptor {
    fn from(config: Arc<ServerConfig>) -> Self {
        Self {
            inner: TokioTlsAcceptor::from(config),
        }
    }
}
