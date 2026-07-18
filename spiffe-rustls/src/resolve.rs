use crate::error::{Error, Result};
use crate::material::{
    cert_chain_from_der_bytes, certified_key_from_chain_and_key, certs_from_der_bytes,
    roots_from_certs, MaterialSnapshot,
};
use crate::prelude::{debug, error, info, warn};
use spiffe::X509Source;
use std::collections::BTreeMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use tokio::sync::watch;
use tokio_util::sync::CancellationToken;

/// Keeps a current snapshot of rustls material and refreshes on `X509Source` rotation.
///
/// If the underlying `X509Source` is closed (shut down, or its background update
/// task dies), the watcher stops updating and [`current`](MaterialWatcher::current)
/// keeps serving the last known-good snapshot indefinitely — including its
/// `roots_by_td`, so trust in a since-removed/defederated trust domain is not
/// revoked until the process restarts. This is logged at `error`, and tracked
/// internally via [`is_live`](MaterialWatcher::is_live), but neither `is_live`
/// nor any other health signal is currently exposed through this crate's
/// public API; wiring one up is a follow-up.
#[derive(Clone, Debug)]
pub(crate) struct MaterialWatcher {
    rx: watch::Receiver<Arc<MaterialSnapshot>>,
    live: Arc<AtomicBool>,
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
    /// If the `X509Source` is later closed, the background task stops and the
    /// watcher freezes on its last known-good snapshot rather than erroring
    /// existing handshakes. This state is only observable via an `error`-level
    /// log line today (see [`is_live`](MaterialWatcher::is_live)).
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
        Self::spawn_watching(source)
    }

    /// Generic core of [`spawn`](Self::spawn), decoupled from the concrete
    /// `X509Source` so the update loop's behaviors (rebuild on rotation,
    /// keep-last-known-good on rebuild failure, stop on source close,
    /// cancellation on drop) can be exercised in tests against a fake source.
    fn spawn_watching<S>(source: Arc<S>) -> Result<Self>
    where
        S: X509WatchSource + Send + Sync + 'static,
        S::Updates: Send + 'static,
    {
        let cancel = CancellationToken::new();
        let token = cancel.clone();

        let handle = tokio::runtime::Handle::try_current()
            .map_err(|tokio::runtime::TryCurrentError { .. }| Error::NoTokioRuntime)?;

        // Subscribe before building the initial snapshot, so a rotation landing in
        // between isn't missed until the next one (subscribing marks the current
        // sequence as "seen").
        let mut updates = source.updated();

        // Build initial material with generation 1
        let initial = Arc::new(build_material(source.as_ref(), 1)?);
        let (tx, rx) = watch::channel(initial);

        let mut generation = 1u64;

        let live = Arc::new(AtomicBool::new(true));
        let live_task = Arc::clone(&live);

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
                                    match tx.send(Arc::new(mat)) {
                                        Ok(()) => {
                                            generation = next_generation;
                                            debug!("updated rustls material from X509Source rotation (generation={generation})");
                                        }
                                        Err(watch::error::SendError(material)) => {
                                            let _unused: Arc<MaterialSnapshot> = material;
                                            // No receivers; stop the background loop
                                            info!("material watcher has no receivers; stopping");
                                            break;
                                        }
                                    }
                                }
                                Err(e) => {
                                    // Keep last known-good material; do not increment generation on failure
                                    error!("failed rebuilding rustls material; keeping previous: {e}");
                                }
                            }
                        } else {
                            live_task.store(false, Ordering::Relaxed);
                            error!("x509 source update channel closed; material watcher frozen on last known-good snapshot");
                            break;
                        }
                    }
                }
            }
        });

        Ok(Self {
            rx,
            live,
            _guard: Arc::new(WatcherGuard { cancel, task }),
        })
    }

    pub(crate) fn current(&self) -> Arc<MaterialSnapshot> {
        self.rx.borrow().clone()
    }

    /// Returns `false` if the background update loop has stopped because the
    /// underlying `X509Source` was closed. Once `false`, [`current`](Self::current)
    /// will keep returning the same frozen snapshot until the process restarts.
    #[cfg_attr(
        not(test),
        expect(dead_code, reason = "observability hook; not yet wired into consumers")
    )]
    pub(crate) fn is_live(&self) -> bool {
        self.live.load(Ordering::Relaxed)
    }
}

/// Builds a federation-aware material snapshot from the bundle set.
fn build_material<S: X509MaterialSource>(source: &S, generation: u64) -> Result<MaterialSnapshot> {
    // `current_svid` and `bundle_set` are two independent reads of the source's
    // snapshot, so a rotation landing between them can pair the SVID from one
    // snapshot with the bundle set from the next. This is benign in practice
    // (SPIRE bundle rotations overlap old/new CAs, and the next update
    // notification rebuilds anyway) but is not a fully coherent read. A truly
    // atomic read would need a combined accessor on `X509Source` returning both
    // from a single snapshot load.
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
            Err(e) => {
                // This is expected when a trust domain's bundle has no valid/acceptable root
                // certificates (e.g., EmptyRootStore). We log and continue with other trust
                // domains. We only fail if no usable root stores can be built for any trust domain.
                warn!("Failed to build root cert store for trust domain {trust_domain}: {e}");
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

/// A subscription that resolves when a source's material may have changed.
///
/// Mirrors [`spiffe::X509SourceUpdates::changed`]'s contract: `Ok` means the
/// caller should re-check the source; `Err` means the source is closed and no
/// further updates will arrive.
trait SourceUpdates: Send {
    fn changed(&mut self) -> impl std::future::Future<Output = Result<()>> + Send;
}

impl SourceUpdates for spiffe::X509SourceUpdates {
    async fn changed(&mut self) -> Result<()> {
        Self::changed(self)
            .await
            .map(|_seq| ())
            .map_err(Error::from)
    }
}

/// A material source that can also be watched for rotation.
///
/// Separate from [`X509MaterialSource`] because `X509Source::updated()` returns
/// a concrete, non-generic subscription type; this associated type lets a
/// fake source in tests provide its own.
trait X509WatchSource: X509MaterialSource {
    type Updates: SourceUpdates;
    fn updated(&self) -> Self::Updates;
}

impl X509WatchSource for X509Source {
    type Updates = spiffe::X509SourceUpdates;

    fn updated(&self) -> Self::Updates {
        self.updated()
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

    /// An RSA private key unrelated to `spiffe_leaf.der`, used to exercise
    /// the key/certificate consistency check.
    fn fixture_mismatched_key_pkcs8_der() -> &'static [u8] {
        include_bytes!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/fixtures/mismatched.key.pkcs8"
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
        /// `None` once [`FakeSource::close_updates`] has been called, simulating
        /// an `X509Source` shutdown: subscribers observe the channel as closed.
        update_tx: Mutex<Option<watch::Sender<u64>>>,
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
            let (update_tx, _rx) = watch::channel(0u64);
            Self {
                svid: Mutex::new(svid),
                bundle_set: Mutex::new(bundle_set),
                update_tx: Mutex::new(Some(update_tx)),
            }
        }

        fn set_svid(&self, svid: Option<Arc<spiffe::X509Svid>>) {
            *self.svid.lock().expect("FakeSource.svid mutex poisoned") = svid;
        }

        /// Notifies subscribers that material may have changed.
        fn notify_update(&self) {
            let guard = self
                .update_tx
                .lock()
                .expect("FakeSource.update_tx mutex poisoned");
            if let Some(tx) = guard.as_ref() {
                tx.send_modify(|seq| *seq += 1);
            }
        }

        /// Simulates the source being closed: existing and future subscribers'
        /// `changed()` calls resolve with an error.
        fn close_updates(&self) {
            *self
                .update_tx
                .lock()
                .expect("FakeSource.update_tx mutex poisoned") = None;
        }
    }

    #[expect(
        clippy::unwrap_in_result,
        reason = "https://github.com/rust-lang/rust-clippy/issues/16476"
    )]
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

    /// Test double for [`SourceUpdates`], backed by a `watch` channel that
    /// [`FakeSource`] can drive directly instead of a real Workload API stream.
    #[derive(Debug)]
    struct FakeUpdates {
        rx: watch::Receiver<u64>,
    }

    impl SourceUpdates for FakeUpdates {
        async fn changed(&mut self) -> Result<()> {
            self.rx
                .changed()
                .await
                .map_err(|watch::error::RecvError { .. }| Error::SourceClosed)
        }
    }

    impl X509WatchSource for FakeSource {
        type Updates = FakeUpdates;

        fn updated(&self) -> Self::Updates {
            let rx = self
                .update_tx
                .lock()
                .expect("FakeSource.update_tx mutex poisoned")
                .as_ref()
                .expect("FakeSource updates already closed")
                .subscribe();
            FakeUpdates { rx }
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
        let src = FakeSource::new(None, Some(Arc::new(make_bundle(td))));

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

    // ---- MaterialWatcher loop tests ----

    fn make_fake_source() -> FakeSource {
        let td = TrustDomain::new("example.org").unwrap();
        FakeSource::new(Some(Arc::new(make_svid())), Some(Arc::new(make_bundle(td))))
    }

    /// Polls `f` until it returns `true` or the deadline elapses, returning
    /// whether it converged. Used to observe the background watcher loop's
    /// (deliberately non-blocking) effects without a fixed sleep.
    async fn wait_until<F: FnMut() -> bool>(mut f: F) -> bool {
        tokio::time::timeout(std::time::Duration::from_secs(2), async {
            while !f() {
                tokio::time::sleep(std::time::Duration::from_millis(5)).await;
            }
        })
        .await
        .is_ok()
    }

    #[tokio::test]
    async fn spawn_watching_without_tokio_runtime_errors() {
        // Run the actual runtime-check + spawn on a plain OS thread with no
        // Tokio context, so `Handle::try_current()` fails as it would for a
        // caller of `MaterialWatcher::spawn` outside any runtime.
        ensure_provider();
        let src = Arc::new(make_fake_source());
        let err = std::thread::spawn(move || MaterialWatcher::spawn_watching(src))
            .join()
            .unwrap()
            .unwrap_err();
        assert!(matches!(err, Error::NoTokioRuntime));
    }

    #[tokio::test]
    async fn spawn_watching_rebuilds_on_update() {
        ensure_provider();

        let src = Arc::new(make_fake_source());
        let watcher = MaterialWatcher::spawn_watching(Arc::clone(&src)).unwrap();
        assert_eq!(watcher.current().generation, 1);

        src.notify_update();
        assert!(
            wait_until(|| watcher.current().generation == 2).await,
            "expected watcher to rebuild to generation 2 after an update notification"
        );
        assert!(watcher.is_live());
    }

    #[tokio::test]
    async fn spawn_watching_keeps_last_known_good_on_rebuild_failure() {
        ensure_provider();

        let src = Arc::new(make_fake_source());
        let watcher = MaterialWatcher::spawn_watching(Arc::clone(&src)).unwrap();
        assert_eq!(watcher.current().generation, 1);

        // Break the source (build_material will now fail with NoSvid) and
        // notify; the watcher must keep serving generation 1 rather than
        // erroring or panicking.
        src.set_svid(None);
        src.notify_update();

        // Give the loop a chance to observe and (fail to) rebuild, then
        // confirm it kept the previous snapshot and is still live.
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        assert_eq!(watcher.current().generation, 1);
        assert!(watcher.is_live());

        // Fix the source and notify again; the loop must still be running
        // and pick up the next successful rebuild as generation 2 (not 3 —
        // the failed attempt must not have incremented the generation).
        src.set_svid(Some(Arc::new(make_svid())));
        src.notify_update();
        assert!(
            wait_until(|| watcher.current().generation == 2).await,
            "expected watcher to recover and rebuild to generation 2"
        );
    }

    #[tokio::test]
    async fn spawn_watching_stops_and_freezes_on_source_close() {
        ensure_provider();

        let src = Arc::new(make_fake_source());
        let watcher = MaterialWatcher::spawn_watching(Arc::clone(&src)).unwrap();
        assert!(watcher.is_live());

        src.close_updates();
        assert!(
            wait_until(|| !watcher.is_live()).await,
            "expected watcher to observe source closure and stop"
        );

        // The frozen snapshot is still served, unchanged.
        assert_eq!(watcher.current().generation, 1);
    }

    // ---- helpers tests ----

    #[test]
    fn roots_from_bundle_der_builds_store() {
        let certs = certs_from_der_bytes([fixture_ca_der()]);
        let store = roots_from_certs(&certs).unwrap();
        assert!(!store.is_empty());
    }

    #[test]
    fn certified_key_from_der_builds_key() {
        ensure_provider();

        let chain = cert_chain_from_der_bytes([fixture_spiffe_leaf_der()]);
        let key = fixture_leaf_key_pkcs8_der();

        let ck = certified_key_from_chain_and_key(chain, key).unwrap();
        assert!(!ck.cert.is_empty());
    }

    #[test]
    fn certified_key_from_der_rejects_mismatched_key() {
        ensure_provider();

        let chain = cert_chain_from_der_bytes([fixture_spiffe_leaf_der()]);
        let key = fixture_mismatched_key_pkcs8_der();

        let err = certified_key_from_chain_and_key(chain, key).unwrap_err();
        assert!(matches!(err, Error::CertifiedKey(_)));
    }
}
