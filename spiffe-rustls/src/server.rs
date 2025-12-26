use crate::error::Result;
use crate::resolve::MaterialWatcher;
use crate::types::{authorize_any, AuthorizeSpiffeId};
use crate::verifier::SpiffeClientCertVerifier;
use rustls::server::ResolvesServerCert;
use rustls::ServerConfig;
use spiffe::{TrustDomain, X509Source};
use std::sync::Arc;

/// Configuration options for [`ServerConfigBuilder`].
///
/// These options control trust bundle selection and client authorization.
#[derive(Clone)]
pub struct ServerConfigOptions {
    /// Trust domain whose bundle is used as the verification root set.
    pub trust_domain: TrustDomain,

    /// Authorization hook invoked with the client SPIFFE ID.
    ///
    /// The hook receives the SPIFFE ID extracted from the client certificate’s
    /// URI SAN and must return `true` to allow the connection.
    pub authorize_client: AuthorizeSpiffeId,
}

impl std::fmt::Debug for ServerConfigOptions {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ServerConfigOptions")
            .field("trust_domain", &self.trust_domain)
            .field("authorize_client", &"<authorize_fn>")
            .finish()
    }
}

impl ServerConfigOptions {
    /// Creates options that authenticate clients but allow any SPIFFE ID.
    ///
    /// This disables authorization while retaining full TLS authentication.
    /// Use only if authorization is performed at another layer.
    pub fn allow_any(trust_domain: TrustDomain) -> Self {
        Self {
            trust_domain,
            authorize_client: authorize_any(),
        }
    }
}

/// Builds a [`rustls::ServerConfig`] backed by a live SPIFFE `X509Source`.
///
/// The resulting server configuration:
///
/// * presents the current SPIFFE X.509 SVID as the server certificate
/// * requires and validates client certificates (mTLS)
/// * authorizes the client by SPIFFE ID (URI SAN)
#[derive(Debug)]
pub struct ServerConfigBuilder {
    source: Arc<X509Source>,
    opts: ServerConfigOptions,
}

impl ServerConfigBuilder {
    /// Creates a new builder from an `X509Source` and options.
    pub fn new(source: Arc<X509Source>, opts: ServerConfigOptions) -> Self {
        Self { source, opts }
    }

    /// Builds the `rustls::ServerConfig`.
    ///
    /// ## Errors
    ///
    /// Returns an error if:
    ///
    /// * the SPIFFE `X509Source` does not currently have an SVID,
    /// * the trust bundle for the configured trust domain is missing,
    /// * rustls crypto providers are not installed,
    /// * or the material watcher cannot be initialized.
    pub fn build(self) -> Result<ServerConfig> {
        crate::crypto::ensure_crypto_provider_installed();

        let watcher = MaterialWatcher::new(self.source, self.opts.trust_domain)?;

        let resolver: Arc<dyn ResolvesServerCert> =
            Arc::new(resolve_server::SpiffeServerCertResolver {
                watcher: watcher.clone(),
            });

        let verifier = Arc::new(SpiffeClientCertVerifier::from_watcher(
            watcher.clone(),
            self.opts.authorize_client,
        ));

        let cfg = ServerConfig::builder()
            .with_client_cert_verifier(verifier)
            .with_cert_resolver(resolver);

        Ok(cfg)
    }
}

mod resolve_server {
    use crate::resolve::MaterialWatcher;
    use rustls::server::ResolvesServerCert;
    use rustls::sign::CertifiedKey;
    use std::sync::Arc;

    #[derive(Clone, Debug)]
    pub(crate) struct SpiffeServerCertResolver {
        pub watcher: MaterialWatcher,
    }

    impl ResolvesServerCert for SpiffeServerCertResolver {
        fn resolve(
            &self,
            _client_hello: rustls::server::ClientHello<'_>,
        ) -> Option<Arc<CertifiedKey>> {
            Some(self.watcher.current().certified_key.clone())
        }
    }
}
