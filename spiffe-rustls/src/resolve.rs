use crate::error::{Error, Result};
use crate::material::{
    cert_chain_from_der_bytes, certified_key_from_chain_and_key, certs_from_der_bytes,
    roots_from_certs, MaterialSnapshot,
};
use crate::prelude::{error, info, warn};
use spiffe::X509Source;
use std::collections::BTreeMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use tokio::sync::watch;
use tokio_util::sync::CancellationToken;

/// Policy for new TLS acquisitions after source closure or watcher termination.
/// Authoritative withdrawal and pending/failed revisions always block under either policy.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum TerminalSourcePolicy {
    /// Retain only the final permitted, successfully converted source revision.
    #[default]
    RetainFinal,
    /// Deny new acquisitions when refresh permanently ends.
    FailClosed,
}

#[derive(Debug)]
struct MaterialState {
    source_revision: u64,
    // Ok is Ready; Err is Blocked. Both belong exclusively to source_revision.
    material: std::result::Result<Arc<MaterialSnapshot>, Arc<Error>>,
}

/// Read-only TLS material and refresh status. Clone to subscribe independently.
/// Retains the source for revision checks, but does not keep the TLS watcher alive.
#[derive(Clone)]
pub struct TlsStatus {
    rx: watch::Receiver<Arc<MaterialState>>,
    source: Arc<dyn X509MaterialSource>,
    live: Arc<AtomicBool>,
    policy: TerminalSourcePolicy,
}

impl std::fmt::Debug for TlsStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TlsStatus")
            .field("current", &self.current())
            .finish_non_exhaustive()
    }
}

/// One observation of current TLS availability and conversion progress.
#[derive(Clone, Debug)]
pub struct TlsStatusSnapshot {
    /// Revision acquired from the authoritative source.
    pub source_revision: u64,
    /// Latest revision processed by the existing material watcher.
    pub applied_revision: u64,
    /// Whether source and material watcher can still refresh.
    /// This does not claim transport connectivity or bounded response age.
    pub refreshing: bool,
    /// Whether new material acquisition is currently permitted.
    pub available: bool,
    /// Current withdrawal, pending-revision, conversion, expiry, or terminal failure.
    pub error: Option<Arc<Error>>,
}

impl TlsStatus {
    /// Observes availability using the same revision gate as TLS callbacks.
    pub fn current(&self) -> TlsStatusSnapshot {
        let applied = self.rx.borrow().clone();
        let source = self.source.observe();
        let refreshing = self.live.load(Ordering::Acquire) && !source.closed;
        let source_revision = source.revision;
        let error = self
            .acquire_from(&applied, source, refreshing)
            .err()
            .map(Arc::new);
        TlsStatusSnapshot {
            source_revision,
            applied_revision: applied.source_revision,
            refreshing,
            available: error.is_none(),
            error,
        }
    }

    /// Waits for a conversion publication or watcher termination acknowledgment.
    /// Notifications coalesce; always inspect `current()` afterward.
    ///
    /// # Errors
    /// Returns an error when the watcher task has ended and no notification remains.
    pub async fn changed(&mut self) -> std::result::Result<(), watch::error::RecvError> {
        self.rx.changed().await
    }

    fn acquire(&self) -> Result<Arc<MaterialSnapshot>> {
        // Load converted material first. The subsequent atomic source observation is
        // this acquisition's linearization point: N-1 cannot pass after publication N.
        // A source change after this observation may affect the next acquisition.
        let applied = self.rx.borrow().clone();
        let source = self.source.observe();
        let refreshing = self.live.load(Ordering::Acquire) && !source.closed;
        self.acquire_from(&applied, source, refreshing)
    }

    fn acquire_from(
        &self,
        applied: &MaterialState,
        source: SourceObservation,
        refreshing: bool,
    ) -> Result<Arc<MaterialSnapshot>> {
        // Permission/usability takes precedence over terminal retention.
        source.material?;
        if source.revision != applied.source_revision {
            return Err(Error::PendingRevision {
                source_revision: source.revision,
                applied_revision: applied.source_revision,
            });
        }
        if !refreshing && self.policy == TerminalSourcePolicy::FailClosed {
            return Err(Error::SourceClosed);
        }
        applied
            .material
            .as_ref()
            .map(Arc::clone)
            .map_err(|error| Error::MaterialUnavailable(Arc::clone(error)))
    }
}

#[derive(Clone, Debug)]
pub(crate) struct MaterialWatcher {
    status: TlsStatus,
    _guard: Arc<WatcherGuard>,
}

#[derive(Debug)]
struct WatcherGuard {
    cancel: CancellationToken,
    task: tokio::task::JoinHandle<()>,
}
impl Drop for WatcherGuard {
    fn drop(&mut self) {
        self.cancel.cancel();
        self.task.abort();
    }
}

// Captured before spawning: terminal status must survive task destruction without a poll.
struct TerminationGuard {
    live: Arc<AtomicBool>,
    tx: watch::Sender<Arc<MaterialState>>,
}
impl Drop for TerminationGuard {
    fn drop(&mut self) {
        self.live.store(false, Ordering::Release);
        self.tx.send_modify(|_| {});
    }
}

impl MaterialWatcher {
    pub(crate) fn spawn(source: Arc<X509Source>, policy: TerminalSourcePolicy) -> Result<Self> {
        Self::spawn_watching(source, policy)
    }

    fn spawn_watching<S>(source: Arc<S>, policy: TerminalSourcePolicy) -> Result<Self>
    where
        S: X509WatchSource + Send + Sync + 'static,
        S::Updates: Send + 'static,
    {
        let handle =
            tokio::runtime::Handle::try_current().map_err(|_no_runtime| Error::NoTokioRuntime)?;
        let mut updates = source.updated();
        let initial_source = source.observe();
        if initial_source.closed {
            return Err(Error::SourceClosed);
        }
        let revision = initial_source.revision;
        let initial = Arc::new(build_material(initial_source, revision + 1)?);
        let (tx, rx) = watch::channel(Arc::new(MaterialState {
            source_revision: revision,
            material: Ok(initial),
        }));
        let live = Arc::new(AtomicBool::new(true));
        let termination = TerminationGuard {
            live: Arc::clone(&live),
            tx: tx.clone(),
        };
        let cancel = CancellationToken::new();
        let token = cancel.clone();
        let task_source = Arc::clone(&source);
        let task = handle.spawn(async move {
            let _termination = termination;
            loop {
                let closed = tokio::select! {
                    () = token.cancelled() => break,
                    result = updates.changed() => result.is_err(),
                };
                // Reread even on closure: the final notification may have coalesced.
                let observation = task_source.observe();
                let source_revision = observation.revision;
                let material = build_material(observation, source_revision + 1)
                    .map(Arc::new)
                    .map_err(Arc::new);
                let published = Arc::new(MaterialState {
                    source_revision,
                    material,
                });
                tx.send_replace(Arc::clone(&published));
                if let Err(cause) = &published.material {
                    error!("TLS material blocked at source revision {source_revision}: {cause}");
                }
                if closed {
                    info!("x509 source closed; material watcher stopped");
                    break;
                }
            }
        });
        Ok(Self {
            status: TlsStatus {
                rx,
                source,
                live,
                policy,
            },
            _guard: Arc::new(WatcherGuard { cancel, task }),
        })
    }

    pub(crate) fn current(&self) -> Result<Arc<MaterialSnapshot>> {
        self.status.acquire()
    }
    pub(crate) fn status(&self) -> TlsStatus {
        self.status.clone()
    }
}

struct SourceObservation {
    revision: u64,
    closed: bool,
    material: Result<(Arc<spiffe::X509Svid>, Arc<spiffe::X509BundleSet>)>,
}

trait X509MaterialSource: Send + Sync {
    fn observe(&self) -> SourceObservation;
}
impl X509MaterialSource for X509Source {
    fn observe(&self) -> SourceObservation {
        let state = self.state();
        SourceObservation {
            revision: state.revision(),
            closed: state.is_closed(),
            material: state.svid().map_err(Error::from).and_then(|svid| {
                state
                    .context()
                    .map(|ctx| (svid, Arc::clone(ctx.bundle_set())))
                    .map_err(Error::from)
            }),
        }
    }
}

fn build_material(observation: SourceObservation, generation: u64) -> Result<MaterialSnapshot> {
    let (svid, bundle_set) = observation.material?;
    let cert_chain = cert_chain_from_der_bytes(
        svid.cert_chain()
            .iter()
            .map(spiffe::cert::Certificate::as_bytes),
    );
    let certified_key =
        certified_key_from_chain_and_key(cert_chain, svid.private_key().as_bytes())?;
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

trait SourceUpdates: Send {
    fn changed(&mut self) -> impl std::future::Future<Output = Result<()>> + Send;
}
impl SourceUpdates for spiffe::X509SourceUpdates {
    async fn changed(&mut self) -> Result<()> {
        Self::changed(self).await.map(|_| ()).map_err(Error::from)
    }
}
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
        material: Mutex<(u64, Option<Arc<spiffe::X509Svid>>, X509BundleSet, bool)>,
        update_tx: Mutex<Option<watch::Sender<u64>>>,
        gate: Option<Arc<tokio::sync::Semaphore>>,
    }
    impl FakeSource {
        fn new(
            svid: Option<Arc<spiffe::X509Svid>>,
            bundle: Option<Arc<spiffe::X509Bundle>>,
        ) -> Self {
            let mut bundles = X509BundleSet::new();
            if let Some(bundle) = bundle {
                bundles.add_bundle(bundle.as_ref().clone());
            }
            let (tx, _) = watch::channel(0);
            Self {
                material: Mutex::new((0, svid, bundles, false)),
                update_tx: Mutex::new(Some(tx)),
                gate: None,
            }
        }
        fn set_svid(&self, svid: Option<Arc<spiffe::X509Svid>>) {
            let mut material = self.material.lock().unwrap();
            material.1 = svid;
        }
        fn notify_update(&self) {
            let mut material = self.material.lock().unwrap();
            material.0 += 1;
            self.update_tx
                .lock()
                .unwrap()
                .as_ref()
                .unwrap()
                .send_replace(material.0);
        }
        fn close_updates(&self) {
            self.material.lock().unwrap().3 = true;
            *self.update_tx.lock().unwrap() = None;
        }
    }
    impl X509MaterialSource for FakeSource {
        fn observe(&self) -> SourceObservation {
            let material = self.material.lock().unwrap();
            SourceObservation {
                revision: material.0,
                closed: material.3,
                material: material
                    .1
                    .clone()
                    .ok_or(Error::NoSvid)
                    .map(|svid| (svid, Arc::new(material.2.clone()))),
            }
        }
    }

    /// Test double for [`SourceUpdates`], backed by a `watch` channel that
    /// [`FakeSource`] can drive directly instead of a real Workload API stream.
    #[derive(Debug)]
    struct FakeUpdates {
        rx: watch::Receiver<u64>,
        gate: Option<Arc<tokio::sync::Semaphore>>,
    }

    impl SourceUpdates for FakeUpdates {
        async fn changed(&mut self) -> Result<()> {
            let result = self
                .rx
                .changed()
                .await
                .map_err(|_closed| Error::SourceClosed);
            if let Some(gate) = &self.gate {
                gate.acquire().await.unwrap().forget();
            }
            result
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
            FakeUpdates {
                rx,
                gate: self.gate.clone(),
            }
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

        let mat = build_material(src.observe(), 1).unwrap();

        assert_ne!(mat.certified_key.cert, []);
        assert!(!mat.roots_by_td.is_empty());
        assert!(mat.roots_by_td.contains_key(&td));
    }

    #[test]
    fn build_material_no_svid() {
        ensure_provider();

        let td = TrustDomain::new("example.org").unwrap();
        let src = FakeSource::new(None, Some(Arc::new(make_bundle(td))));

        let err = build_material(src.observe(), 1).unwrap_err();
        assert!(matches!(err, Error::NoSvid));
    }

    #[test]
    fn build_material_no_bundle() {
        ensure_provider();

        let src = FakeSource::new(Some(Arc::new(make_svid())), None);

        let err = build_material(src.observe(), 1).unwrap_err();
        assert!(matches!(err, Error::NoUsableRootStores));
    }

    // ---- MaterialWatcher loop tests ----

    fn make_fake_source() -> FakeSource {
        let td = TrustDomain::new("example.org").unwrap();
        FakeSource::new(Some(Arc::new(make_svid())), Some(Arc::new(make_bundle(td))))
    }

    #[tokio::test]
    async fn spawn_watching_without_tokio_runtime_errors() {
        // Run the actual runtime-check + spawn on a plain OS thread with no
        // Tokio context, so `Handle::try_current()` fails as it would for a
        // caller of `MaterialWatcher::spawn` outside any runtime.
        ensure_provider();
        let src = Arc::new(make_fake_source());
        let err = std::thread::spawn(move || {
            MaterialWatcher::spawn_watching(src, TerminalSourcePolicy::RetainFinal)
        })
        .join()
        .unwrap()
        .unwrap_err();
        assert!(matches!(err, Error::NoTokioRuntime));
    }

    #[tokio::test]
    async fn spawn_watching_rebuilds_on_update() {
        ensure_provider();

        let src = Arc::new(make_fake_source());
        let watcher =
            MaterialWatcher::spawn_watching(Arc::clone(&src), TerminalSourcePolicy::RetainFinal)
                .unwrap();
        assert_eq!(watcher.current().unwrap().generation, 1);

        let mut status = watcher.status();
        src.notify_update();
        status.changed().await.unwrap();
        assert_eq!(watcher.current().unwrap().generation, 2);
        assert!(status.current().available);
    }

    #[tokio::test]
    async fn spawn_watching_blocks_failed_revision_and_recovers() {
        ensure_provider();
        let src = Arc::new(make_fake_source());
        let watcher =
            MaterialWatcher::spawn_watching(Arc::clone(&src), TerminalSourcePolicy::RetainFinal)
                .unwrap();
        let mut status = watcher.status();
        src.set_svid(None);
        src.notify_update();
        assert!(
            watcher.current().is_err(),
            "publication blocks even before watcher acknowledgment"
        );
        status.changed().await.unwrap();
        assert_eq!(status.current().applied_revision, 1);
        assert!(!status.current().available);
        src.set_svid(Some(Arc::new(make_svid())));
        src.notify_update();
        status.changed().await.unwrap();
        assert_eq!(watcher.current().unwrap().generation, 3);
    }

    #[tokio::test]
    async fn terminal_policies_preserve_only_final_permitted_revision() {
        ensure_provider();
        for policy in [
            TerminalSourcePolicy::RetainFinal,
            TerminalSourcePolicy::FailClosed,
        ] {
            let src = Arc::new(make_fake_source());
            let watcher = MaterialWatcher::spawn_watching(Arc::clone(&src), policy).unwrap();
            let mut status = watcher.status();
            src.close_updates();
            assert_eq!(
                watcher.current().is_ok(),
                policy == TerminalSourcePolicy::RetainFinal
            );
            status.changed().await.unwrap();
            assert!(!status.current().refreshing);
            assert_eq!(
                watcher.current().is_ok(),
                policy == TerminalSourcePolicy::RetainFinal
            );
        }
        let src = Arc::new(make_fake_source());
        let watcher =
            MaterialWatcher::spawn_watching(Arc::clone(&src), TerminalSourcePolicy::RetainFinal)
                .unwrap();
        let mut status = watcher.status();
        src.set_svid(None);
        src.notify_update();
        src.close_updates();
        watcher.current().unwrap_err();
        status.changed().await.unwrap();
        watcher.current().unwrap_err();
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
        assert_ne!(ck.cert, []);
    }

    #[test]
    fn certified_key_from_der_rejects_mismatched_key() {
        ensure_provider();

        let chain = cert_chain_from_der_bytes([fixture_spiffe_leaf_der()]);
        let key = fixture_mismatched_key_pkcs8_der();

        let err = certified_key_from_chain_and_key(chain, key).unwrap_err();
        assert!(matches!(err, Error::CertifiedKey(_)));
    }
    fn configs_for_watcher(
        watcher: &MaterialWatcher,
    ) -> (Arc<rustls::ClientConfig>, Arc<rustls::ServerConfig>) {
        let mut client = rustls::ClientConfig::builder()
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(
                crate::verifier::SpiffeServerCertVerifier::new(
                    Arc::new(watcher.clone()),
                    crate::authorizer::any(),
                    crate::TrustDomainPolicy::default(),
                ),
            ))
            .with_client_cert_resolver(Arc::new(
                crate::client::resolve_client::SpiffeClientCertResolver {
                    watcher: watcher.clone(),
                },
            ));
        client.resumption = rustls::client::Resumption::disabled();
        let mut server = rustls::ServerConfig::builder()
            .with_client_cert_verifier(Arc::new(crate::verifier::SpiffeClientCertVerifier::new(
                Arc::new(watcher.clone()),
                crate::authorizer::any(),
                crate::TrustDomainPolicy::default(),
            )))
            .with_cert_resolver(Arc::new(
                crate::server::resolve_server::SpiffeServerCertResolver {
                    watcher: watcher.clone(),
                },
            ));
        server.session_storage = Arc::new(rustls::server::NoServerSessionStorage {});
        server.send_tls13_tickets = 0;
        (Arc::new(client), Arc::new(server))
    }

    #[expect(
        clippy::unwrap_in_result,
        clippy::panic_in_result_fn,
        reason = "in-memory test I/O and fixed fixture name are infallible; protocol errors are returned"
    )]
    fn handshake(
        client: Arc<rustls::ClientConfig>,
        server: Arc<rustls::ServerConfig>,
    ) -> std::result::Result<(), rustls::Error> {
        use std::io::Cursor;
        let mut client = rustls::ClientConnection::new(client, "example.org".try_into().unwrap())?;
        let mut server = rustls::ServerConnection::new(server)?;
        for _ in 0..32 {
            let mut bytes = Vec::new();
            client.write_tls(&mut bytes).unwrap();
            if !bytes.is_empty() {
                server.read_tls(&mut Cursor::new(bytes)).unwrap();
                server.process_new_packets()?;
            }
            let mut bytes = Vec::new();
            server.write_tls(&mut bytes).unwrap();
            if !bytes.is_empty() {
                client.read_tls(&mut Cursor::new(bytes)).unwrap();
                client.process_new_packets()?;
            }
            if !client.is_handshaking() && !server.is_handshaking() {
                return Ok(());
            }
        }
        panic!("handshake stalled");
    }

    #[tokio::test]
    #[expect(
        clippy::used_underscore_binding,
        reason = "test aborts the retained watcher task at the publication barrier"
    )]
    async fn stalled_watcher_coalesced_revisions_and_late_subscribers_cannot_use_old_cache() {
        ensure_provider();
        let mut fake = make_fake_source();
        let gate = Arc::new(tokio::sync::Semaphore::new(0));
        fake.gate = Some(Arc::clone(&gate));
        let src = Arc::new(fake);
        let watcher =
            MaterialWatcher::spawn_watching(Arc::clone(&src), TerminalSourcePolicy::RetainFinal)
                .unwrap();
        let (client, server) = configs_for_watcher(&watcher);
        let peer_src = Arc::new(make_fake_source());
        let peer_watcher =
            MaterialWatcher::spawn_watching(peer_src, TerminalSourcePolicy::RetainFinal).unwrap();
        let (peer_client, peer_server) = configs_for_watcher(&peer_watcher);
        handshake(Arc::clone(&client), Arc::clone(&peer_server)).unwrap();
        handshake(Arc::clone(&peer_client), Arc::clone(&server)).unwrap(); // populate both verifier caches
        src.notify_update();
        let mut late = watcher.status();
        assert_eq!(late.current().source_revision, 1);
        assert_eq!(late.current().applied_revision, 0);
        assert!(matches!(
            watcher.current(),
            Err(Error::PendingRevision { .. })
        ));
        handshake(Arc::clone(&client), Arc::clone(&peer_server)).unwrap_err();
        handshake(Arc::clone(&peer_client), Arc::clone(&server)).unwrap_err();
        src.set_svid(None);
        src.notify_update(); // coalesced failure remains authoritative
        gate.add_permits(1);
        late.changed().await.unwrap();
        assert_eq!(late.current().applied_revision, 2);
        assert!(!late.current().available);
        src.set_svid(Some(Arc::new(make_svid())));
        src.notify_update();
        gate.add_permits(1);
        late.changed().await.unwrap();
        assert_eq!(late.current().applied_revision, 3);
        handshake(Arc::clone(&client), Arc::clone(&peer_server)).unwrap();
        handshake(Arc::clone(&peer_client), Arc::clone(&server)).unwrap();

        // A stopped watcher must not retain the superseded Ready revision forever.
        src.notify_update();
        assert_eq!(late.current().source_revision, 4);
        assert_eq!(late.current().applied_revision, 3);
        watcher._guard.task.abort();
        late.changed().await.unwrap(); // task-drop guard acknowledges watcher termination
        let stopped = late.current();
        assert!(!stopped.refreshing);
        assert!(!stopped.available);
        assert!(matches!(
            stopped.error.as_deref(),
            Some(Error::PendingRevision {
                source_revision: 4,
                applied_revision: 3,
            })
        ));
        handshake(client, peer_server).unwrap_err();
        handshake(peer_client, server).unwrap_err();
    }

    #[tokio::test]
    async fn unusable_roots_and_domain_removal_never_restore_prior_roots() {
        ensure_provider();
        let src = Arc::new(make_fake_source());
        let watcher =
            MaterialWatcher::spawn_watching(Arc::clone(&src), TerminalSourcePolicy::RetainFinal)
                .unwrap();
        let mut status = watcher.status();
        let (client, server) = configs_for_watcher(&watcher);
        let peer = MaterialWatcher::spawn_watching(
            Arc::new(make_fake_source()),
            TerminalSourcePolicy::RetainFinal,
        )
        .unwrap();
        let (peer_client, peer_server) = configs_for_watcher(&peer);
        handshake(Arc::clone(&client), Arc::clone(&peer_server)).unwrap();
        handshake(Arc::clone(&peer_client), Arc::clone(&server)).unwrap();
        let td = TrustDomain::new("example.org").unwrap();
        for empty in [false, true] {
            {
                let mut material = src.material.lock().unwrap();
                material.2 = X509BundleSet::new();
                if !empty {
                    material.2.add_bundle(spiffe::X509Bundle::new(td.clone()));
                }
            }
            src.notify_update();
            status.changed().await.unwrap();
            assert!(
                matches!(watcher.current(),Err(Error::MaterialUnavailable(cause)) if matches!(cause.as_ref(),Error::NoUsableRootStores))
            );
            handshake(Arc::clone(&client), Arc::clone(&peer_server)).unwrap_err();
            handshake(Arc::clone(&peer_client), Arc::clone(&server)).unwrap_err();
        }
        {
            src.material.lock().unwrap().2.add_bundle(make_bundle(td));
        }
        src.notify_update();
        status.changed().await.unwrap();
        handshake(client, peer_server).unwrap();
        handshake(peer_client, server).unwrap();
    }

    #[tokio::test]
    async fn unusable_current_domain_is_removed_while_other_current_trust_remains_ready() {
        ensure_provider();
        let src = Arc::new(make_fake_source());
        let foreign = TrustDomain::new("foreign.example").unwrap();
        src.material
            .lock()
            .unwrap()
            .2
            .add_bundle(make_bundle(foreign.clone()));
        let watcher =
            MaterialWatcher::spawn_watching(Arc::clone(&src), TerminalSourcePolicy::RetainFinal)
                .unwrap();
        assert!(watcher
            .current()
            .unwrap()
            .roots_by_td
            .contains_key(&foreign));
        let mut status = watcher.status();
        src.material
            .lock()
            .unwrap()
            .2
            .add_bundle(spiffe::X509Bundle::new(foreign.clone()));
        src.notify_update();
        status.changed().await.unwrap();
        let current = watcher.current().unwrap();
        assert_eq!(current.generation, 2);
        assert!(!current.roots_by_td.contains_key(&foreign));
        assert!(current
            .roots_by_td
            .contains_key(&TrustDomain::new("example.org").unwrap()));
        assert!(status.current().available);
    }

    #[test]
    fn watcher_destruction_before_first_poll_reports_terminal_without_runtime() {
        ensure_provider();
        for policy in [
            TerminalSourcePolicy::RetainFinal,
            TerminalSourcePolicy::FailClosed,
        ] {
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap();
            let watcher = runtime.block_on(async {
                MaterialWatcher::spawn_watching(Arc::new(make_fake_source()), policy).unwrap()
            });
            drop(runtime);
            assert!(!watcher.status().current().refreshing);
            assert_eq!(
                watcher.current().is_ok(),
                policy == TerminalSourcePolicy::RetainFinal
            );
        }
    }
}
