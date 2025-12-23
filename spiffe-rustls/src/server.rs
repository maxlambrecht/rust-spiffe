use crate::error::Result;
use crate::resolve::MaterialWatcher;
use crate::types::{AuthorizeSpiffeId, authorize_any};
use crate::verifier::SpiffeClientCertVerifier;
use rustls::ServerConfig;
use rustls::server::ResolvesServerCert;
use spiffe::{TrustDomain, X509Source};
use std::sync::Arc;

/// Options for building a SPIFFE-aware `rustls::ServerConfig`.
#[derive(Clone)]
pub struct ServerConfigOptions {
    /// Trust domain whose bundle is used as the verification root set.
    pub trust_domain: TrustDomain,

    /// Authorization hook invoked with the client SPIFFE ID.
    ///
    /// Returning `false` rejects the peer even if the certificate chain is valid.
    pub authorize_client: AuthorizeSpiffeId,
}

impl ServerConfigOptions {
    /// Creates options that accept any client SPIFFE ID for the given trust domain.
    ///
    /// Authentication still happens via bundle verification; only authorization is permissive.
    pub fn allow_any(trust_domain: TrustDomain) -> Self {
        Self {
            trust_domain,
            authorize_client: authorize_any(),
        }
    }
}

/// Builds a `rustls::ServerConfig` backed by an [`spiffe::X509Source`].
///
/// The resulting config:
/// - presents the current SVID as the server certificate
/// - requires and verifies client certificates (mTLS) using the trust domain bundle
/// - authorizes the client by SPIFFE ID (URI SAN)
///
/// New handshakes use the latest SVID/bundle material after rotations.
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
    pub async fn build(self) -> Result<ServerConfig> {
        // crate::crypto::ensure_crypto_provider_installed();

        let watcher = MaterialWatcher::new(self.source, self.opts.trust_domain).await?;
        let mat = watcher.current();

        let resolver: Arc<dyn ResolvesServerCert> =
            Arc::new(resolve_server::SpiffeServerCertResolver { watcher });

        let verifier = Arc::new(SpiffeClientCertVerifier::new(
            mat.roots.clone(),
            self.opts.authorize_client,
        )?);

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
