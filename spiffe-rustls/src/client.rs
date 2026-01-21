use crate::authorizer::Authorizer;
use crate::error::Result;
use crate::policy::TrustDomainPolicy;
use crate::resolve::MaterialWatcher;
use crate::verifier::SpiffeServerCertVerifier;
use rustls::client::ResolvesClientCert;
use rustls::ClientConfig;
use spiffe::X509Source;
use std::sync::Arc;

/// Function type for customizing a `ClientConfig`.
type ClientConfigCustomizer = Box<dyn FnOnce(&mut ClientConfig) + Send>;

/// Builds a [`rustls::ClientConfig`] backed by a live SPIFFE `X509Source`.
///
/// The resulting client configuration:
///
/// * presents the current SPIFFE X.509 SVID as the client certificate
/// * validates the server certificate chain against trust bundles from the Workload API
/// * authorizes the server by SPIFFE ID (URI SAN)
///
/// The builder retains an `Arc<X509Source>`. When the underlying SVID or trust
/// bundle is rotated by the SPIRE agent, **new TLS handshakes automatically use
/// the updated material**.
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
/// Server authorization is performed by invoking the provided [`Authorizer`] with
/// the server's SPIFFE ID extracted from the certificate's URI SAN.
///
/// Use [`authorizer::any`] to disable authorization while retaining full TLS authentication.
///
/// # Examples
///
/// ```no_run
/// use spiffe_rustls::{authorizer, mtls_client, AllowList};
/// use std::collections::BTreeSet;
///
/// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
/// let source = spiffe::X509Source::new().await?;
///
/// // Pass string literals directly - exact() and trust_domains() will convert them
/// let allowed_server_ids = [
///     "spiffe://example.org/myservice",
///     "spiffe://example.org/myservice2",
/// ];
///
/// let mut allowed_trust_domains = BTreeSet::new();
/// allowed_trust_domains.insert("example.org".try_into()?);
///
/// let client_config = mtls_client(source)
///     .authorize(authorizer::exact(allowed_server_ids)?)
///     .trust_domain_policy(AllowList(allowed_trust_domains))
///     .build()?;
/// # Ok(())
/// # }
/// ```
pub struct ClientConfigBuilder {
    source: Arc<X509Source>,
    authorizer: Arc<dyn Authorizer>,
    trust_domain_policy: TrustDomainPolicy,
    alpn_protocols: Vec<Vec<u8>>,
    config_customizer: Option<ClientConfigCustomizer>,
}

impl std::fmt::Debug for ClientConfigBuilder {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ClientConfigBuilder")
            .field("source", &"<Arc<X509Source>>")
            .field("authorizer", &"<Arc<dyn Authorizer>>")
            .field("trust_domain_policy", &self.trust_domain_policy)
            .field("alpn_protocols", &self.alpn_protocols)
            .field("config_customizer", &self.config_customizer.is_some())
            .finish()
    }
}

impl ClientConfigBuilder {
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

    /// Sets the authorization policy for server SPIFFE IDs.
    ///
    /// Accepts any type that implements `Authorizer`, including closures.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use spiffe_rustls::{authorizer, mtls_client};
    ///
    /// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// let source = spiffe::X509Source::new().await?;
    ///
    /// // Using a convenience constructor - pass string literals directly
    /// let config = mtls_client(source.clone())
    ///     .authorize(authorizer::exact([
    ///         "spiffe://example.org/service",
    ///         "spiffe://example.org/service2",
    ///     ])?)
    ///     .build()?;
    ///
    /// // Using a closure
    /// let config = mtls_client(source.clone())
    ///     .authorize(|id: &spiffe::SpiffeId| id.path().starts_with("/api/"))
    ///     .build()?;
    ///
    /// // Using the Any authorizer (default)
    /// let config = mtls_client(source)
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
    /// use spiffe_rustls::mtls_client;
    ///
    /// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// let source = spiffe::X509Source::new().await?;
    /// let config = mtls_client(source)
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

    /// Applies a customizer function to the `ClientConfig` after it's built.
    ///
    /// This is an **advanced** API for configuration not directly exposed by the builder.
    /// The customizer is called **last**, after all other builder settings (including
    /// ALPN) have been applied, allowing you to override any configuration.
    ///
    /// **Warning:** Do not modify or replace the verifier or client certificate resolver,
    /// as they are required for SPIFFE authentication and authorization. Safe to modify:
    /// ALPN, cipher suites, protocol versions, and other non-security-critical settings.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use spiffe_rustls::mtls_client;
    ///
    /// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// let source = spiffe::X509Source::new().await?;
    /// let config = mtls_client(source)
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
        F: FnOnce(&mut ClientConfig) + Send + 'static,
    {
        self.config_customizer = Some(Box::new(customizer));
        self
    }

    /// Builds the `rustls::ClientConfig`.
    ///
    /// The returned configuration:
    ///
    /// * presents the current SPIFFE X.509 SVID as the client certificate
    /// * validates the server certificate chain against trust bundles from the Workload API
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
    /// * building the underlying Rustls certificate verifier fails
    pub fn build(self) -> Result<ClientConfig> {
        crate::crypto::ensure_crypto_provider_installed();

        let watcher = MaterialWatcher::spawn(self.source)?;

        let resolver: Arc<dyn ResolvesClientCert> =
            Arc::new(resolve_client::SpiffeClientCertResolver {
                watcher: watcher.clone(),
            });

        let verifier = Arc::new(SpiffeServerCertVerifier::new(
            Arc::new(watcher) as Arc<dyn crate::verifier::MaterialProvider>,
            self.authorizer,
            self.trust_domain_policy,
        ));

        let mut cfg = ClientConfig::builder()
            .dangerous()
            .with_custom_certificate_verifier(verifier)
            .with_client_cert_resolver(resolver);

        cfg.alpn_protocols = self.alpn_protocols;

        // Apply customizer last
        if let Some(customizer) = self.config_customizer {
            customizer(&mut cfg);
        }

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
