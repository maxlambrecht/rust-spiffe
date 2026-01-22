use crate::authorizer::Authorizer;
use crate::error::Result;
use crate::policy::TrustDomainPolicy;
use crate::resolve::MaterialWatcher;
use crate::verifier::SpiffeClientCertVerifier;
use rustls::server::ResolvesServerCert;
use rustls::ServerConfig;
use spiffe::X509Source;
use std::sync::Arc;

/// Function type for customizing a `ServerConfig`.
type ServerConfigCustomizer = Box<dyn FnOnce(&mut ServerConfig) + Send>;

/// Builds a [`rustls::ServerConfig`] backed by a live SPIFFE `X509Source`.
///
/// The resulting server configuration:
///
/// * presents the current SPIFFE X.509 SVID as the server certificate
/// * requires and validates client certificates (mTLS)
/// * authorizes the client by SPIFFE ID (URI SAN)
///
/// ## Trust Domain Selection
///
/// The builder uses the bundle set from `X509Source`, which may contain bundles
/// for multiple trust domains (when SPIFFE federation is configured). The verifier
/// automatically selects the correct bundle based on the peer's SPIFFE ID—no
/// manual configuration is required. You can optionally restrict which trust
/// domains are accepted using [`Self::trust_domain_policy`].
///
/// ## Authorization
///
/// Client authorization is performed by invoking the provided [`Authorizer`] with
/// the client's SPIFFE ID extracted from the certificate's URI SAN.
///
/// Use [`authorizer::any`] to disable authorization while retaining full TLS authentication.
///
/// # Examples
///
/// ```no_run
/// use spiffe::{TrustDomain, X509Source};
/// use spiffe_rustls::{authorizer, mtls_server, LocalOnly};
///
/// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
/// let source = X509Source::new().await?;
///
/// // Pass string literals directly - trust_domains() will convert them
/// let allowed_trust_domains = ["example.org"];
///
/// let local_trust_domain: TrustDomain = "example.org".try_into()?;
///
/// let server_config = mtls_server(source)
///     .authorize(authorizer::trust_domains(allowed_trust_domains)?)
///     .trust_domain_policy(LocalOnly(local_trust_domain))
///     .build()?;
/// # Ok(())
/// # }
/// ```
pub struct ServerConfigBuilder {
    source: Arc<X509Source>,
    authorizer: Arc<dyn Authorizer>,
    trust_domain_policy: TrustDomainPolicy,
    alpn_protocols: Vec<Vec<u8>>,
    config_customizer: Option<ServerConfigCustomizer>,
}

impl std::fmt::Debug for ServerConfigBuilder {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ServerConfigBuilder")
            .field("source", &"<Arc<X509Source>>")
            .field("authorizer", &"<Arc<dyn Authorizer>>")
            .field("trust_domain_policy", &self.trust_domain_policy)
            .field("alpn_protocols", &self.alpn_protocols)
            .field("config_customizer", &self.config_customizer.is_some())
            .finish()
    }
}

impl ServerConfigBuilder {
    /// Creates a new builder from an `X509Source`.
    ///
    /// Defaults:
    /// - Authorization: accepts any SPIFFE ID (authentication only)
    /// - Trust domain policy: `AnyInBundleSet` (uses all bundles from the Workload API)
    /// - ALPN protocols: empty (no ALPN)
    pub fn new(source: X509Source) -> Self {
        Self {
            source: Arc::new(source),
            authorizer: Arc::new(crate::authorizer::any()),
            trust_domain_policy: TrustDomainPolicy::default(),
            alpn_protocols: Vec::new(),
            config_customizer: None,
        }
    }

    /// Sets the authorization policy for client SPIFFE IDs.
    ///
    /// Accepts any type that implements `Authorizer`, including closures.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use spiffe_rustls::{authorizer, mtls_server};
    ///
    /// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// let source = spiffe::X509Source::new().await?;
    ///
    /// // Pass string literals directly
    /// let config = mtls_server(source.clone())
    ///     .authorize(authorizer::trust_domains([
    ///         "example.org",
    ///     ])?)
    ///     .build()?;
    ///
    /// // Using a closure
    /// let config = mtls_server(source.clone())
    ///     .authorize(|id: &spiffe::SpiffeId| id.path().starts_with("/api/"))
    ///     .build()?;
    ///
    /// // Using the Any authorizer (default)
    /// let config = mtls_server(source)
    ///     .authorize(authorizer::any())
    ///     .build()?;
    /// # Ok(())
    /// # }
    /// ```
    #[must_use]
    pub fn authorize<A: Authorizer>(mut self, authorizer: A) -> Self {
        self.authorizer = Arc::new(authorizer);
        self
    }

    /// Sets the trust domain policy.
    ///
    /// Defaults to `AnyInBundleSet` (uses all bundles from the Workload API).
    #[must_use]
    pub fn trust_domain_policy(mut self, policy: TrustDomainPolicy) -> Self {
        self.trust_domain_policy = policy;
        self
    }

    /// Sets the ALPN (Application-Layer Protocol Negotiation) protocols.
    ///
    /// The protocols are advertised during the TLS handshake. Common values:
    /// - `b"h2"` for HTTP/2 (required for gRPC)
    /// - `b"http/1.1"` for HTTP/1.1
    ///
    /// Protocols should be specified in order of preference (most preferred first).
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use spiffe_rustls::mtls_server;
    ///
    /// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// let source = spiffe::X509Source::new().await?;
    /// let config = mtls_server(source)
    ///     .with_alpn_protocols([b"h2"])
    ///     .build()?;
    /// # Ok(())
    /// # }
    /// ```
    #[must_use]
    pub fn with_alpn_protocols<I, P>(mut self, protocols: I) -> Self
    where
        I: IntoIterator<Item = P>,
        P: AsRef<[u8]>,
    {
        self.alpn_protocols = protocols.into_iter().map(|p| p.as_ref().to_vec()).collect();
        self
    }

    /// Applies a customizer function to the `ServerConfig` after it's built.
    ///
    /// This is an **advanced** API for configuration not directly exposed by the builder.
    /// The customizer is called **last**, after all other builder settings (including
    /// ALPN) have been applied, allowing you to override any configuration.
    ///
    /// **Warning:** Do not modify or replace the verifier or server certificate resolver,
    /// as they are required for SPIFFE authentication and authorization. Safe to modify:
    /// ALPN, cipher suites, protocol versions, and other non-security-critical settings.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use spiffe_rustls::mtls_server;
    ///
    /// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// let source = spiffe::X509Source::new().await?;
    /// let config = mtls_server(source)
    ///     .with_config_customizer(|cfg| {
    ///         // Example: adjust cipher suite preferences
    ///     })
    ///     .build()?;
    /// # Ok(())
    /// # }
    /// ```
    #[must_use]
    pub fn with_config_customizer<F>(mut self, customizer: F) -> Self
    where
        F: FnOnce(&mut ServerConfig) + Send + 'static,
    {
        self.config_customizer = Some(Box::new(customizer));
        self
    }

    /// Builds the `rustls::ServerConfig`.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    ///
    /// * the SPIFFE `X509Source` does not currently have an SVID,
    /// * rustls crypto providers are not installed,
    /// * or the material watcher cannot be initialized.
    pub fn build(self) -> Result<ServerConfig> {
        crate::crypto::ensure_crypto_provider_installed();

        let watcher = MaterialWatcher::spawn(self.source)?;

        let resolver: Arc<dyn ResolvesServerCert> =
            Arc::new(resolve_server::SpiffeServerCertResolver {
                watcher: watcher.clone(),
            });

        let verifier = Arc::new(SpiffeClientCertVerifier::new(
            Arc::new(watcher) as Arc<dyn crate::verifier::MaterialProvider>,
            self.authorizer,
            self.trust_domain_policy,
        ));

        let mut cfg = ServerConfig::builder()
            .with_client_cert_verifier(verifier)
            .with_cert_resolver(resolver);

        cfg.alpn_protocols = self.alpn_protocols;

        // Apply customizer last
        if let Some(customizer) = self.config_customizer {
            customizer(&mut cfg);
        }

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
