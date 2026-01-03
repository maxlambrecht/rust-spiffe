use crate::error::{Error, Result};
use crate::material::{
    cert_chain_from_der_bytes, certified_key_from_chain_and_key, certs_from_der_bytes,
    roots_from_certs, MaterialSnapshot,
};
use crate::prelude::{debug, error, info, warn};
use spiffe::X509Source;
use std::collections::BTreeMap;
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
    /// Spawns a background task to watch an `X509Source` and keep rustls material updated.
    ///
    /// This function **requires a Tokio runtime** to be available (via `Handle::try_current()`).
    /// It reads the current material immediately and then spawns a background task to apply
    /// updates when the `X509Source` rotates.
    ///
    /// The watcher builds material from the **entire bundle set**, enabling
    /// federation by default.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - the source does not currently have an SVID,
    /// - the bundle set is empty or invalid,
    /// - or there is no Tokio runtime available to spawn the update task (returns `Error::NoTokioRuntime`).
    ///
    /// ## Runtime Requirements
    ///
    /// This function must be called from within a Tokio runtime context. If you're using
    /// `tokio::main` or `tokio::test`, this is automatic. Otherwise, ensure you have a
    /// runtime handle available.
    pub(crate) fn spawn(source: Arc<X509Source>) -> Result<Self> {
        let cancel = CancellationToken::new();
        let token = cancel.clone();

        let handle = tokio::runtime::Handle::try_current().map_err(|_| Error::NoTokioRuntime)?;

        // Build initial material with generation 1
        let initial = Arc::new(build_material(source.as_ref(), 1)?);
        let (tx, rx) = watch::channel(initial);

        let mut updates = source.updated();
        let mut generation = 1u64;

        let task = handle.spawn(async move {
            loop {
                tokio::select! {
                    () = token.cancelled() => {
                        debug!("material watcher cancelled; stopping");
                        break;
                    }

                    res = updates.changed() => {
                        if res.is_ok() {
                            // Update notification received; rebuild material
                            // Only increment generation on successful rebuild+send
                            let next_generation = generation + 1;
                            match build_material(source.as_ref(), next_generation) {
                                Ok(mat) => {
                                    if let Ok(()) = tx.send(Arc::new(mat)) {
                                        generation = next_generation;
                                        debug!("updated rustls material from X509Source rotation (generation={generation})");
                                    } else {
                                        // No receivers; stop the background loop
                                        info!("material watcher has no receivers; stopping");
                                        break;
                                    }
                                }
                                Err(_e) => {
                                    // Keep last known-good material; do not increment generation on failure
                                    error!("failed rebuilding rustls material; keeping previous: {_e}");
                                }
                            }
                        } else {
                            info!("x509 source update channel closed; stopping material watcher");
                            break;
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

/// Builds a federation-aware material snapshot from the bundle set.
fn build_material<S: X509MaterialSource>(source: &S, generation: u64) -> Result<MaterialSnapshot> {
    let svid = source.current_svid()?;
    let bundle_set = source.bundle_set()?;

    // Build certified key from SVID
    let cert_chain = cert_chain_from_der_bytes(
        svid.cert_chain()
            .iter()
            .map(spiffe::cert::Certificate::as_bytes),
    );
    let certified_key =
        certified_key_from_chain_and_key(cert_chain, svid.private_key().as_bytes())?;

    // Build root cert stores for each trust domain in the bundle set
    let mut roots_by_td = BTreeMap::new();
    for (trust_domain, bundle) in bundle_set.iter() {
        let root_certs = certs_from_der_bytes(
            bundle
                .authorities()
                .iter()
                .map(spiffe::cert::Certificate::as_bytes),
        );
        match roots_from_certs(&root_certs) {
            Ok(roots) => {
                roots_by_td.insert(trust_domain.clone(), roots);
            }
            Err(_e) => {
                // This is expected when a trust domain's bundle has no valid/acceptable root
                // certificates (e.g., EmptyRootStore). We log and continue with other trust
                // domains. We only fail if no usable root stores can be built for any trust domain.
                warn!("Failed to build root cert store for trust domain {trust_domain}: {_e}");
            }
        }
    }

    if roots_by_td.is_empty() {
        return Err(Error::NoUsableRootStores);
    }

    Ok(MaterialSnapshot {
        generation,
        certified_key,
        roots_by_td,
    })
}

trait X509MaterialSource {
    fn current_svid(&self) -> Result<Arc<spiffe::X509Svid>>;
    fn bundle_set(&self) -> Result<Arc<spiffe::X509BundleSet>>;
}

impl X509MaterialSource for X509Source {
    fn current_svid(&self) -> Result<Arc<spiffe::X509Svid>> {
        self.svid().map_err(Error::from)
    }

    fn bundle_set(&self) -> Result<Arc<spiffe::X509BundleSet>> {
        self.bundle_set().map_err(Error::from)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use spiffe::{TrustDomain, X509BundleSet};
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
        pub bundle_set: Mutex<X509BundleSet>,
    }

    impl FakeSource {
        fn new(
            svid: Option<Arc<spiffe::X509Svid>>,
            bundle: Option<Arc<spiffe::X509Bundle>>,
        ) -> Self {
            let mut bundle_set = X509BundleSet::new();
            if let Some(b) = bundle {
                bundle_set.add_bundle((*b).clone());
            }
            Self {
                svid: Mutex::new(svid),
                bundle_set: Mutex::new(bundle_set),
            }
        }

        #[allow(dead_code)]
        fn set_svid(&self, svid: Option<spiffe::X509Svid>) {
            *self.svid.lock().unwrap() = svid.map(Arc::new);
        }

        #[allow(dead_code)]
        fn set_bundle(&self, bundle: Option<spiffe::X509Bundle>) {
            let mut set = self.bundle_set.lock().unwrap();
            *set = X509BundleSet::new();
            if let Some(b) = bundle {
                set.add_bundle(b);
            }
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

        fn bundle_set(&self) -> Result<Arc<X509BundleSet>> {
            Ok(Arc::new(
                self.bundle_set
                    .lock()
                    .expect("FakeSource.bundle_set mutex poisoned")
                    .clone(),
            ))
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

        let mat = build_material(&src, 1).unwrap();

        assert!(!mat.certified_key.cert.is_empty());
        assert!(!mat.roots_by_td.is_empty());
        assert!(mat.roots_by_td.contains_key(&td));
    }

    #[test]
    fn build_material_no_svid() {
        ensure_provider();

        let td = TrustDomain::new("example.org").unwrap();
        let src = FakeSource::new(None, Some(Arc::new(make_bundle(td.clone()))));

        let err = build_material(&src, 1).unwrap_err();
        assert!(matches!(err, Error::NoSvid));
    }

    #[test]
    fn build_material_no_bundle() {
        ensure_provider();

        let src = FakeSource::new(Some(Arc::new(make_svid())), None);

        let err = build_material(&src, 1).unwrap_err();
        assert!(matches!(err, Error::NoUsableRootStores));
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
