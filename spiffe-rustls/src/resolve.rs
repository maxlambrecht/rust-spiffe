use crate::error::{Error, Result};
use crate::material::{
    cert_chain_from_der_bytes, certified_key_from_chain_and_key, certs_from_der_bytes,
    roots_from_certs, MaterialSnapshot,
};
use log::{debug, error, info};
use spiffe::{BundleSource, TrustDomain, X509Source};
use std::sync::Arc;
use tokio::sync::watch;
use tokio_util::sync::CancellationToken;

/// Keeps a current snapshot of rustls material and refreshes on `X509Source` rotation.
#[derive(Clone, Debug)]
pub(crate) struct MaterialWatcher {
    rx: watch::Receiver<Arc<MaterialSnapshot>>,
    _guard: Arc<WatcherGuard>,
}

#[derive(Debug)]
struct WatcherGuard {
    cancel: CancellationToken,
    task: tokio::task::JoinHandle<()>,
}

impl Drop for WatcherGuard {
    fn drop(&mut self) {
        // Best-effort: stop the loop and abort if it's still running.
        self.cancel.cancel();
        self.task.abort();
    }
}

impl MaterialWatcher {
    /// Create a new watcher using an already-initialized [`X509Source`].
    ///
    /// This function is synchronous: it reads current material immediately and
    /// then spawns a background task to apply updates.
    ///
    /// ## Errors
    ///
    /// Returns an error if:
    /// - the source does not currently have an SVID,
    /// - the trust bundle for `trust_domain` is missing,
    /// - or there is no Tokio runtime available to spawn the update task.
    pub fn new(source: Arc<X509Source>, trust_domain: TrustDomain) -> Result<Self> {
        let cancel = CancellationToken::new();
        let token = cancel.clone();

        let handle = tokio::runtime::Handle::try_current()
            .map_err(|_| Error::Internal("no Tokio runtime available".into()))?;

        let initial = Arc::new(build_material(&*source, &trust_domain, 1)?);
        let (tx, rx) = watch::channel(initial);

        let mut updates = source.updated();

        let task = handle.spawn(async move {
            let mut generation: u64 = 1;
            loop {
                tokio::select! {
                    () = token.cancelled() => {
                        debug!("material watcher cancelled; stopping");
                        break;
                    }

                    res = updates.changed() => {
                        if res.is_err() {
                            info!("x509 source update channel closed; stopping material watcher");
                            break;
                        }

                        match build_material(&*source, &trust_domain, generation + 1) {
                            Ok(mat) => {
                                generation += 1;
                                let _ = tx.send(Arc::new(mat));
                                debug!("updated rustls material from X509Source rotation");
                            }
                            Err(e) => {
                                // Keep last known-good material.
                                error!("failed rebuilding rustls material; keeping previous: {e}");
                            }
                        }
                    }
                }
            }
        });

        Ok(Self {
            rx,
            _guard: Arc::new(WatcherGuard { cancel, task }),
        })
    }

    pub fn current(&self) -> Arc<MaterialSnapshot> {
        self.rx.borrow().clone()
    }
}

fn build_material<S: X509MaterialSource>(
    source: &S,
    trust_domain: &TrustDomain,
    generation: u64,
) -> Result<MaterialSnapshot> {
    let svid = source.current_svid()?;

    let bundle = source
        .bundle_for(trust_domain)?
        .ok_or_else(|| Error::NoBundle(trust_domain.to_string()))?;

    let cert_chain = cert_chain_from_der_bytes(
        svid.cert_chain()
            .iter()
            .map(spiffe::cert::Certificate::as_bytes),
    );
    let root_certs = certs_from_der_bytes(
        bundle
            .authorities()
            .iter()
            .map(spiffe::cert::Certificate::as_bytes),
    );

    let certified_key =
        certified_key_from_chain_and_key(cert_chain, svid.private_key().as_bytes())?;
    let roots = roots_from_certs(&root_certs)?;

    Ok(MaterialSnapshot {
        generation,
        certified_key,
        roots,
    })
}

trait X509MaterialSource {
    fn current_svid(&self) -> Result<Arc<spiffe::X509Svid>>;
    fn bundle_for(&self, td: &TrustDomain) -> Result<Option<Arc<spiffe::X509Bundle>>>;
}

impl X509MaterialSource for X509Source {
    fn current_svid(&self) -> Result<Arc<spiffe::X509Svid>> {
        self.svid()
            .map_err(|e| Error::Internal(format!("get_svid: {e}")))
    }

    fn bundle_for(&self, td: &TrustDomain) -> Result<Option<Arc<spiffe::X509Bundle>>> {
        self.bundle_for_trust_domain(td)
            .map_err(|e| Error::Internal(format!("get_bundle_for_trust_domain: {e}")))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    fn ensure_provider() {
        crate::crypto::ensure_crypto_provider_installed();
    }

    fn fixture_spiffe_leaf_der() -> &'static [u8] {
        include_bytes!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/fixtures/spiffe_leaf.der"
        ))
    }

    fn fixture_ca_der() -> &'static [u8] {
        include_bytes!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/fixtures/ca.der"
        ))
    }

    fn fixture_leaf_key_pkcs8_der() -> &'static [u8] {
        include_bytes!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/fixtures/leaf.key.pkcs8"
        ))
    }

    fn make_svid() -> spiffe::X509Svid {
        spiffe::X509Svid::parse_from_der(fixture_spiffe_leaf_der(), fixture_leaf_key_pkcs8_der())
            .unwrap()
    }

    fn make_bundle(td: TrustDomain) -> spiffe::X509Bundle {
        spiffe::X509Bundle::parse_from_der(td, fixture_ca_der()).unwrap()
    }

    #[derive(Debug)]
    struct FakeSource {
        pub svid: Mutex<Option<Arc<spiffe::X509Svid>>>,
        pub bundle: Mutex<Option<Arc<spiffe::X509Bundle>>>,
    }

    impl FakeSource {
        fn new(
            svid: Option<Arc<spiffe::X509Svid>>,
            bundle: Option<Arc<spiffe::X509Bundle>>,
        ) -> Self {
            Self {
                svid: Mutex::new(svid),
                bundle: Mutex::new(bundle),
            }
        }

        #[allow(dead_code)]
        fn set_svid(&self, svid: Option<spiffe::X509Svid>) {
            *self.svid.lock().unwrap() = svid.map(Arc::new);
        }

        #[allow(dead_code)]
        fn set_bundle(&self, bundle: Option<spiffe::X509Bundle>) {
            *self.bundle.lock().unwrap() = bundle.map(Arc::new);
        }
    }

    impl X509MaterialSource for FakeSource {
        fn current_svid(&self) -> Result<Arc<spiffe::X509Svid>> {
            self.svid
                .lock()
                .expect("FakeSource.svid mutex poisoned")
                .clone()
                .ok_or(Error::NoSvid)
        }

        fn bundle_for(&self, _td: &TrustDomain) -> Result<Option<Arc<spiffe::X509Bundle>>> {
            Ok(self
                .bundle
                .lock()
                .expect("FakeSource.bundle mutex poisoned")
                .clone())
        }
    }

    // ---- build_material tests ----

    #[test]
    fn build_material_ok() {
        ensure_provider();

        let td = TrustDomain::new("example.org").unwrap();
        let src = FakeSource::new(
            Some(Arc::new(make_svid())),
            Some(Arc::new(make_bundle(td.clone()))),
        );

        let mat = build_material(&src, &td, 1).unwrap();

        assert!(!mat.certified_key.cert.is_empty());
        assert!(!mat.roots.is_empty());
    }

    #[test]
    fn build_material_no_svid() {
        ensure_provider();

        let td = TrustDomain::new("example.org").unwrap();
        let src = FakeSource::new(None, Some(Arc::new(make_bundle(td.clone()))));

        let err = build_material(&src, &td, 1).unwrap_err();
        assert!(matches!(err, Error::NoSvid));
    }

    #[test]
    fn build_material_no_bundle() {
        ensure_provider();

        let td = TrustDomain::new("example.org").unwrap();
        let src = FakeSource::new(Some(Arc::new(make_svid())), None);

        let err = build_material(&src, &td, 1).unwrap_err();
        assert!(matches!(err, Error::NoBundle(_)));
    }

    // ---- helpers tests ----

    #[test]
    fn roots_from_bundle_der_builds_store() {
        let certs = crate::material::certs_from_der_bytes([fixture_ca_der()]);
        let store = crate::material::roots_from_certs(&certs).unwrap();
        assert!(!store.is_empty());
    }

    #[test]
    fn certified_key_from_der_builds_key() {
        ensure_provider();

        let chain = crate::material::cert_chain_from_der_bytes([fixture_spiffe_leaf_der()]);
        let key = fixture_leaf_key_pkcs8_der();

        let ck = crate::material::certified_key_from_chain_and_key(chain, key).unwrap();
        assert!(!ck.cert.is_empty());
    }
}
