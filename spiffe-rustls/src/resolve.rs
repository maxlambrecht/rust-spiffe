use crate::error::{Error, Result};
use crate::material::{MaterialSnapshot, certified_key_from_der, roots_from_bundle_der};
use log::{debug, error, info};
use spiffe::{BundleSource, SvidSource, TrustDomain, X509Source};
use std::sync::Arc;
use tokio::sync::watch;
use tokio_util::sync::CancellationToken;

/// Keeps a current snapshot of rustls material and refreshes on X509Source rotation.
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
    pub async fn new(source: Arc<X509Source>, trust_domain: TrustDomain) -> Result<Self> {
        let initial = Arc::new(build_material(&*source, &trust_domain)?);
        let (tx, rx) = watch::channel(initial);

        let cancel = CancellationToken::new();
        let token = cancel.clone();
        let mut updates = source.updated();

        let task = tokio::spawn(async move {
            loop {
                tokio::select! {
                    _ = token.cancelled() => {
                        debug!("material watcher cancelled; stopping");
                        break;
                    }

                    res = updates.changed() => {
                        if res.is_err() {
                            info!("x509 source update channel closed; stopping material watcher");
                            break;
                        }

                        match build_material(&*source, &trust_domain) {
                            Ok(mat) => {
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
) -> Result<MaterialSnapshot> {
    let svid = source.current_svid()?.ok_or(Error::NoSvid)?;

    let bundle = source
        .bundle_for(trust_domain)?
        .ok_or_else(|| Error::NoBundle(trust_domain.to_string()))?;

    let cert_chain_der: Vec<Vec<u8>> = svid
        .cert_chain()
        .iter()
        .map(|c| c.content().to_vec())
        .collect();

    let key_der = svid.private_key().content();

    let bundle_authorities: Vec<Vec<u8>> = bundle
        .authorities()
        .iter()
        .map(|c| c.content().to_vec())
        .collect();

    let certified_key = certified_key_from_der(&cert_chain_der, key_der)?;
    let roots = roots_from_bundle_der(&bundle_authorities)?;

    Ok(MaterialSnapshot {
        certified_key,
        roots,
    })
}

trait X509MaterialSource {
    fn current_svid(&self) -> Result<Option<spiffe::X509Svid>>;
    fn bundle_for(&self, td: &TrustDomain) -> Result<Option<spiffe::X509Bundle>>;
}

impl X509MaterialSource for X509Source {
    fn current_svid(&self) -> Result<Option<spiffe::X509Svid>> {
        <X509Source as SvidSource>::get_svid(self)
            .map_err(|e| Error::Internal(format!("get_svid: {e}")))
    }

    fn bundle_for(&self, td: &TrustDomain) -> Result<Option<spiffe::X509Bundle>> {
        <X509Source as BundleSource>::get_bundle_for_trust_domain(self, td)
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
        svid: Mutex<Option<spiffe::X509Svid>>,
        bundle: Mutex<Option<spiffe::X509Bundle>>,
    }

    impl FakeSource {
        fn new(svid: Option<spiffe::X509Svid>, bundle: Option<spiffe::X509Bundle>) -> Self {
            Self {
                svid: Mutex::new(svid),
                bundle: Mutex::new(bundle),
            }
        }

        #[allow(dead_code)]
        fn set_svid(&self, svid: Option<spiffe::X509Svid>) {
            *self.svid.lock().unwrap() = svid;
        }

        #[allow(dead_code)]
        fn set_bundle(&self, bundle: Option<spiffe::X509Bundle>) {
            *self.bundle.lock().unwrap() = bundle;
        }
    }

    impl X509MaterialSource for FakeSource {
        fn current_svid(&self) -> Result<Option<spiffe::X509Svid>> {
            Ok(self.svid.lock().unwrap().clone())
        }

        fn bundle_for(&self, _td: &TrustDomain) -> Result<Option<spiffe::X509Bundle>> {
            Ok(self.bundle.lock().unwrap().clone())
        }
    }

    // ---- build_material tests ----

    #[test]
    fn build_material_ok() {
        ensure_provider();

        let td = TrustDomain::new("example.org").unwrap();
        let src = FakeSource::new(Some(make_svid()), Some(make_bundle(td.clone())));

        let mat = build_material(&src, &td).unwrap();

        assert!(!mat.certified_key.cert.is_empty());
        assert!(!mat.roots.is_empty());
    }

    #[test]
    fn build_material_no_svid() {
        ensure_provider();

        let td = TrustDomain::new("example.org").unwrap();
        let src = FakeSource::new(None, Some(make_bundle(td.clone())));

        let err = build_material(&src, &td).unwrap_err();
        assert!(matches!(err, Error::NoSvid));
    }

    #[test]
    fn build_material_no_bundle() {
        ensure_provider();

        let td = TrustDomain::new("example.org").unwrap();
        let src = FakeSource::new(Some(make_svid()), None);

        let err = build_material(&src, &td).unwrap_err();
        assert!(matches!(err, Error::NoBundle(_)));
    }

    // ---- helpers tests ----

    #[test]
    fn roots_from_bundle_der_builds_store() {
        let store = roots_from_bundle_der(&[fixture_ca_der().to_vec()]).unwrap();
        assert!(!store.is_empty());
    }

    #[test]
    fn certified_key_from_der_builds_key() {
        ensure_provider();

        let cert_chain = vec![fixture_spiffe_leaf_der().to_vec()];
        let key = fixture_leaf_key_pkcs8_der();

        let ck = certified_key_from_der(&cert_chain, key).unwrap();
        assert!(!ck.cert.is_empty());
    }
}
