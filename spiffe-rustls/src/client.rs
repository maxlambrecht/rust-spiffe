use crate::error::Result;
use crate::resolve::MaterialWatcher;
use crate::types::{authorize_any, AuthorizeSpiffeId};
use crate::verifier::SpiffeServerCertVerifier;
use rustls::client::ResolvesClientCert;
use rustls::ClientConfig;
use spiffe::{TrustDomain, X509Source};
use std::sync::Arc;

/// Configuration options for [`ClientConfigBuilder`].
///
/// These options control trust bundle selection and server authorization.
#[derive(Clone)]
pub struct ClientConfigOptions {
    /// Trust domain whose bundle is used as the verification root set.
    pub trust_domain: TrustDomain,

    /// Authorization hook invoked with the server SPIFFE ID.
    ///
    /// The hook receives the SPIFFE ID extracted from the server certificate’s
    /// URI SAN and must return `true` to allow the connection.
    pub authorize_server: AuthorizeSpiffeId,
}

impl std::fmt::Debug for ClientConfigOptions {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ClientConfigOptions")
            .field("trust_domain", &self.trust_domain)
            .field("authorize_server", &"<authorize_fn>")
            .finish()
    }
}

impl ClientConfigOptions {
    /// Creates options that authenticate the server but allow any SPIFFE ID.
    ///
    /// This disables authorization while retaining full TLS authentication.
    /// Use only if authorization is performed at another layer.
    pub fn allow_any(trust_domain: TrustDomain) -> Self {
        Self {
            trust_domain,
            authorize_server: authorize_any(),
        }
    }
}

/// Builds a [`rustls::ClientConfig`] backed by a live SPIFFE `X509Source`.
///
/// The resulting client configuration:
///
/// * presents the current SPIFFE X.509 SVID as the client certificate
/// * validates the server certificate chain against the trust domain bundle
/// * authorizes the server by SPIFFE ID (URI SAN)
///
/// The builder retains an `Arc<X509Source>`. When the underlying SVID or trust
/// bundle is rotated by the SPIRE agent, **new TLS handshakes automatically use
/// the updated material**.
///
/// ## Authorization
///
/// Server authorization is performed by invoking the provided
/// [`AuthorizeSpiffeId`] hook with the server’s SPIFFE ID extracted from the
/// certificate’s URI SAN.
///
/// Use [`ClientConfigOptions::allow_any`] to disable authorization while
/// retaining full TLS authentication.
#[derive(Debug)]
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
    ///
    /// The returned configuration:
    ///
    /// * presents the current SPIFFE X.509 SVID as the client certificate
    /// * validates the server certificate chain against the configured trust domain
    /// * authorizes the server by SPIFFE ID (URI SAN)
    ///
    /// The configuration is backed by a live [`X509Source`]. When the underlying
    /// SVID or trust bundle is rotated by the SPIRE agent, **new TLS handshakes
    /// automatically use the updated material**.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    ///
    /// * the Rustls crypto provider is not installed
    /// * no current X.509 SVID is available from the `X509Source`
    /// * the trust bundle for the configured trust domain is missing
    /// * building the underlying Rustls certificate verifier fails
    pub fn build(self) -> Result<ClientConfig> {
        crate::crypto::ensure_crypto_provider_installed();

        let watcher = MaterialWatcher::new(self.source, self.opts.trust_domain)?;

        let resolver: Arc<dyn ResolvesClientCert> =
            Arc::new(resolve_client::SpiffeClientCertResolver {
                watcher: watcher.clone(),
            });

        let verifier = Arc::new(SpiffeServerCertVerifier::from_watcher(
            watcher.clone(),
            self.opts.authorize_server,
        ));

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
