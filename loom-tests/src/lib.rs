//! Loom protocol model of rust-spiffe TLS material revision gating.
//!
//! Every item mirrors one production construct, named in its doc comment. The
//! model keeps the order and atomicity of each production synchronization step
//! and replaces the opaque dependencies (`arc_swap::ArcSwap`,
//! `tokio::sync::watch`) with Loom-instrumented stand-ins that provide only the
//! guarantees production relies on.
//!
//! This verifies an abstract protocol. It does not execute production code, and
//! it does not check the `ArcSwap` or tokio implementations. See `README.md`.

use loom::sync::atomic::{AtomicU64, Ordering};
use loom::sync::{Condvar, Mutex};
use std::sync::Arc as StdArc;

// ---------------------------------------------------------------------------
// Model variant selection
// ---------------------------------------------------------------------------

const fn enabled(on: bool) -> usize {
    if on {
        1
    } else {
        0
    }
}

/// Number of enabled `defect-*`/`variant-*` features; at most one is allowed.
pub const ENABLED_VARIANTS: usize = enabled(cfg!(feature = "defect-torn-observe"))
    + enabled(cfg!(feature = "defect-no-revision-gate"))
    + enabled(cfg!(feature = "defect-notify-before-store"))
    + enabled(cfg!(feature = "defect-observe-before-subscribe"))
    + enabled(cfg!(feature = "variant-source-first"))
    + enabled(cfg!(feature = "variant-torn-revision-first"));

const _: () = match ENABLED_VARIANTS {
    0 | 1 => (),
    _ => panic!("enable at most one defect-* or variant-* feature"),
};

/// Name of the compiled model variant (`baseline` when no feature is enabled).
pub const VARIANT: &str = if cfg!(feature = "defect-torn-observe") {
    "defect-torn-observe"
} else if cfg!(feature = "defect-no-revision-gate") {
    "defect-no-revision-gate"
} else if cfg!(feature = "defect-notify-before-store") {
    "defect-notify-before-store"
} else if cfg!(feature = "defect-observe-before-subscribe") {
    "defect-observe-before-subscribe"
} else if cfg!(feature = "variant-source-first") {
    "variant-source-first"
} else if cfg!(feature = "variant-torn-revision-first") {
    "variant-torn-revision-first"
} else {
    "baseline"
};

// ---------------------------------------------------------------------------
// Dependency stand-ins
// ---------------------------------------------------------------------------

/// Stand-in for `arc_swap::ArcSwap<T>`.
///
/// Assumption: `load_full` and `store` are linearizable, and a load returns
/// exactly one previously stored `Arc` (never a mix). The `Mutex` gives Loom a
/// schedulable linearization point. It does not model `ArcSwap`'s lock-free
/// internals, which Loom cannot see.
#[derive(Debug)]
pub struct Register<T> {
    cell: Mutex<StdArc<T>>,
}

impl<T> Register<T> {
    pub fn new(value: T) -> Self {
        Self {
            cell: Mutex::new(StdArc::new(value)),
        }
    }

    pub fn load_full(&self) -> StdArc<T> {
        StdArc::clone(&self.cell.lock().unwrap())
    }

    pub fn store(&self, value: T) {
        *self.cell.lock().unwrap() = StdArc::new(value);
    }
}

/// Stand-in for `tokio::sync::watch` (version-counting, coalescing).
///
/// Assumptions, matching tokio's documented contract (tokio loom-tests `watch`
/// internally in `src/sync/tests/loom_watch.rs`):
/// - `send_replace` atomically replaces the value and bumps the version;
/// - `subscribe` marks the version current at subscription time as seen;
/// - `changed` returns once the version differs from the last seen version,
///   and never misses a send that happens after subscription.
#[derive(Debug)]
pub struct Watch {
    state: Mutex<WatchState>,
    cv: Condvar,
}

#[derive(Debug)]
struct WatchState {
    version: u64,
    value: u64,
}

#[derive(Debug)]
pub struct Subscription {
    seen: u64,
}

impl Watch {
    fn new(value: u64) -> Self {
        Self {
            state: Mutex::new(WatchState { version: 0, value }),
            cv: Condvar::new(),
        }
    }

    fn send_replace(&self, value: u64) -> u64 {
        let mut state = self.state.lock().unwrap();
        let prev = std::mem::replace(&mut state.value, value);
        state.version += 1;
        drop(state);
        self.cv.notify_all();
        prev
    }

    fn subscribe(&self) -> Subscription {
        Subscription {
            seen: self.state.lock().unwrap().version,
        }
    }

    /// Blocks like `Receiver::changed().await`. The source never closes in this
    /// model, so the `RecvError` path is absent.
    fn changed(&self, sub: &mut Subscription) {
        let mut state = self.state.lock().unwrap();
        while state.version == sub.seen {
            state = self.cv.wait(state).unwrap();
        }
        sub.seen = state.version;
    }
}

// ---------------------------------------------------------------------------
// spiffe: X509Source
// ---------------------------------------------------------------------------

/// Identity material: the selected SVID's key and the trust-bundle set.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Material {
    pub key: u64,
    pub roots: u64,
}

/// `spiffe::X509SourceState` (`spiffe/src/x509_source/source.rs`): context,
/// selection, permission and revision in one immutable value.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Snapshot {
    pub revision: u64,
    pub withdrawn: bool,
    pub material: Material,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Withdrawn;

/// `spiffe_rustls::resolve::SourceObservation` (revision and material only).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Observation {
    pub revision: u64,
    pub material: Result<Material, Withdrawn>,
}

fn permitted(snapshot: &Snapshot) -> Result<Material, Withdrawn> {
    if snapshot.withdrawn {
        Err(Withdrawn)
    } else {
        Ok(snapshot.material)
    }
}

/// `spiffe::x509_source::source::Inner` (`snapshot`, `update_seq`, `update_tx`).
#[derive(Debug)]
pub struct Source {
    snapshot: Register<Snapshot>,
    update_seq: AtomicU64,
    update_tx: Watch,
}

impl Source {
    pub fn new(initial: Snapshot) -> Self {
        Self {
            snapshot: Register::new(initial),
            update_seq: AtomicU64::new(0),
            update_tx: Watch::new(0),
        }
    }

    /// `Inner::apply_update` (Applied path) and `Inner::withdraw`.
    ///
    /// Single writer: only the supervisor task calls these in production, and
    /// only the writer thread calls this in the model (`load_full` + `store` is
    /// not a compare-and-swap). The unchanged-redelivery and repeated-withdrawal
    /// early returns are not modelled; every call publishes a new revision.
    pub fn publish(&self, withdrawn: bool, material: Material) {
        let current = self.snapshot.load_full();
        let next = Snapshot {
            revision: current.revision + 1,
            withdrawn,
            material,
        };
        #[cfg(not(feature = "defect-notify-before-store"))]
        {
            self.snapshot.store(next);
            self.notify_update();
        }
        #[cfg(feature = "defect-notify-before-store")]
        {
            self.notify_update();
            self.snapshot.store(next);
        }
    }

    /// `Inner::notify_update`: `Relaxed` sequence increment, then `send_replace`.
    fn notify_update(&self) {
        let next = self.update_seq.fetch_add(1, Ordering::Relaxed) + 1;
        let _prev = self.update_tx.send_replace(next);
    }

    /// `X509Source::updated()`.
    pub fn updated(&self) -> Subscription {
        self.update_tx.subscribe()
    }

    /// `X509SourceUpdates::changed()` without the shutdown arm.
    pub fn changed(&self, sub: &mut Subscription) {
        self.update_tx.changed(sub);
    }

    /// `<X509Source as X509MaterialSource>::observe()`: a single `state()` call,
    /// that is one `snapshot.load_full()`, feeds both revision and material.
    pub fn observe(&self) -> Observation {
        #[cfg(not(any(
            feature = "defect-torn-observe",
            feature = "variant-torn-revision-first"
        )))]
        {
            let state = self.snapshot.load_full();
            Observation {
                revision: state.revision,
                material: permitted(&state),
            }
        }
        // Defect: two independent loads, material before revision.
        #[cfg(feature = "defect-torn-observe")]
        {
            let for_material = self.snapshot.load_full();
            let for_revision = self.snapshot.load_full();
            Observation {
                revision: for_revision.revision,
                material: permitted(&for_material),
            }
        }
        // Benign: two independent loads, revision before material (the field
        // order of the production `SourceObservation` literal if each field
        // called `state()` separately).
        #[cfg(feature = "variant-torn-revision-first")]
        {
            let for_revision = self.snapshot.load_full();
            let for_material = self.snapshot.load_full();
            Observation {
                revision: for_revision.revision,
                material: permitted(&for_material),
            }
        }
    }
}

// ---------------------------------------------------------------------------
// spiffe-rustls: MaterialWatcher and TlsStatus::acquire
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Blocked;

/// `spiffe_rustls::resolve::MaterialState`: Ready or Blocked, owned by exactly
/// one source revision.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MaterialState {
    pub source_revision: u64,
    pub material: Result<Material, Blocked>,
}

/// `build_material`: conversion fails (Blocked) when the observation is not
/// permitted. Certificate parsing and conversion failures are out of scope.
fn convert(observation: Observation) -> MaterialState {
    MaterialState {
        source_revision: observation.revision,
        material: observation.material.map_err(|Withdrawn| Blocked),
    }
}

/// Output of [`watcher_start`].
#[derive(Debug)]
pub struct WatcherStart {
    pub applied: Register<MaterialState>,
    pub subscription: Subscription,
    /// Revision of the initial conversion, returned so the model's watcher
    /// loop needs no extra (schedule-point) load to learn it.
    pub initial_revision: u64,
}

/// Synchronous prefix of `MaterialWatcher::spawn_watching`, run on the builder
/// thread before the watcher task exists.
pub fn watcher_start(source: &Source) -> WatcherStart {
    #[cfg(not(feature = "defect-observe-before-subscribe"))]
    let (subscription, initial) = {
        let subscription = source.updated();
        let initial = source.observe();
        (subscription, initial)
    };
    #[cfg(feature = "defect-observe-before-subscribe")]
    let (subscription, initial) = {
        let initial = source.observe();
        let subscription = source.updated();
        (subscription, initial)
    };
    let initial = convert(initial);
    WatcherStart {
        applied: Register::new(initial),
        subscription,
        initial_revision: initial.source_revision,
    }
}

/// One iteration of the `spawn_watching` task loop: wait, re-read, publish.
/// Returns the published source revision.
pub fn watcher_step(
    source: &Source,
    applied: &Register<MaterialState>,
    subscription: &mut Subscription,
) -> u64 {
    source.changed(subscription);
    let observation = source.observe();
    let published = convert(observation);
    applied.store(published);
    published.source_revision
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AcquireError {
    Withdrawn,
    PendingRevision { source: u64, applied: u64 },
    MaterialUnavailable,
}

/// Result of one acquisition plus the exact source observation it used.
///
/// Returning the observation is model-only instrumentation: it is a value the
/// acquisition already read, so it adds no schedule point or synchronization.
#[derive(Clone, Copy, Debug)]
pub struct Acquisition {
    pub result: Result<(u64, Material), AcquireError>,
    pub observation: Observation,
}

/// `TlsStatus::acquire`: load converted material, then observe the source. On
/// success returns the material and the revision it was converted from.
pub fn acquire(source: &Source, applied: &Register<MaterialState>) -> Acquisition {
    #[cfg(not(feature = "variant-source-first"))]
    let (applied, observation) = {
        let applied = applied.load_full();
        let observation = source.observe();
        (applied, observation)
    };
    // Benign: observe the source first, then load converted material.
    #[cfg(feature = "variant-source-first")]
    let (applied, observation) = {
        let observation = source.observe();
        let applied = applied.load_full();
        (applied, observation)
    };
    Acquisition {
        result: acquire_from(&applied, observation),
        observation,
    }
}

/// `TlsStatus::acquire_from` with `refreshing == true` (the terminal-policy
/// branch is not modelled).
fn acquire_from(
    applied: &MaterialState,
    source: Observation,
) -> Result<(u64, Material), AcquireError> {
    // Permission/usability takes precedence over everything else.
    source
        .material
        .map_err(|Withdrawn| AcquireError::Withdrawn)?;
    #[cfg(not(feature = "defect-no-revision-gate"))]
    if source.revision != applied.source_revision {
        return Err(AcquireError::PendingRevision {
            source: source.revision,
            applied: applied.source_revision,
        });
    }
    applied
        .material
        .map(|material| (applied.source_revision, material))
        .map_err(|Blocked| AcquireError::MaterialUnavailable)
}
