use crate::error::Result;
use crate::resolve::MaterialWatcher;
use crate::types::{authorize_any, AuthorizeSpiffeId};
use crate::verifier::SpiffeServerCertVerifier;
use rustls::client::ResolvesClientCert;
use rustls::ClientConfig;
use spiffe::{TrustDomain, X509Source};
use std::sync::Arc;

/// Options for building a SPIFFE-aware `rustls::ClientConfig`.
#[derive(Clone)]
pub struct ClientConfigOptions {
    /// Trust domain whose bundle is used as the verification root set.
    pub trust_domain: TrustDomain,

    /// Authorization hook invoked with the server SPIFFE ID.
    ///
    /// Returning `false` rejects the peer even if the certificate chain is valid.
    pub authorize_server: AuthorizeSpiffeId,
}

impl ClientConfigOptions {
    /// Creates options that accept any server SPIFFE ID for the given trust domain.
    ///
    /// Authentication still happens via bundle verification; only authorization is permissive.
    pub fn allow_any(trust_domain: TrustDomain) -> Self {
        Self {
            trust_domain,
            authorize_server: authorize_any(),
        }
    }
}

/// Builds a `rustls::ClientConfig` backed by an [`spiffe::X509Source`].
///
/// The resulting config:
/// - presents the current SVID as the client certificate
/// - verifies server certificates using the trust domain bundle
/// - authorizes the server by SPIFFE ID (URI SAN)
///
/// New handshakes use the latest SVID/bundle material after rotations.
pub struct ClientConfigBuilder {
    source: Arc<X509Source>,
    opts: ClientConfigOptions,
}

impl ClientConfigBuilder {
    /// Creates a new builder from an `X509Source` and options.
    pub fn new(source: Arc<X509Source>, opts: ClientConfigOptions) -> Self {
        Self { source, opts }
    }

    /// Builds the `rustls::ClientConfig`.
    pub async fn build(self) -> Result<ClientConfig> {
        crate::crypto::ensure_crypto_provider_installed();

        let watcher = MaterialWatcher::new(self.source, self.opts.trust_domain).await?;

        let resolver: Arc<dyn ResolvesClientCert> =
            Arc::new(resolve_client::SpiffeClientCertResolver {
                watcher: watcher.clone(),
            });

        let verifier = Arc::new(SpiffeServerCertVerifier::new(
            Arc::new(watcher.clone()),
            self.opts.authorize_server,
        )?);

        let cfg = ClientConfig::builder()
            .dangerous()
            .with_custom_certificate_verifier(verifier)
            .with_client_cert_resolver(resolver);

        Ok(cfg)
    }
}

mod resolve_client {
    use crate::resolve::MaterialWatcher;
    use rustls::client::ResolvesClientCert;
    use rustls::sign::CertifiedKey;
    use std::sync::Arc;

    #[derive(Clone, Debug)]
    pub(crate) struct SpiffeClientCertResolver {
        pub watcher: MaterialWatcher,
    }

    impl ResolvesClientCert for SpiffeClientCertResolver {
        fn resolve(
            &self,
            _acceptable_issuers: &[&[u8]],
            _sigschemes: &[rustls::SignatureScheme],
        ) -> Option<Arc<CertifiedKey>> {
            Some(self.watcher.current().certified_key.clone())
        }

        fn has_certs(&self) -> bool {
            true
        }
    }
}
