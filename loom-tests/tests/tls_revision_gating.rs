//! Loom model of TLS material revision gating. See `loom-tests/README.md`.
//!
//! Each scenario is one `#[test]`. The compiled variant (`spiffe_loom_models::
//! VARIANT`) selects the expected outcome for every scenario:
//!
//! - baseline and benign variants must complete exploration with the exact
//!   canonical interleaving count;
//! - each defect must be detected for its expected reason. A pass, or a failure
//!   for any other reason, fails the test.

use loom::sync::Arc;
use loom::thread;
use spiffe_loom_models::{
    acquire, watcher_start, watcher_step, AcquireError, Acquisition, Material, Snapshot, Source,
    VARIANT,
};
use std::panic::{self, AssertUnwindSafe};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::mpsc;
use std::time::{Duration, Instant};
use tracing_subscriber::util::SubscriberInitExt;
use tracing_subscriber::{fmt, EnvFilter};

// ---------------------------------------------------------------------------
// Scenarios
// ---------------------------------------------------------------------------

const K0: Material = Material {
    key: 10,
    roots: 100,
};
const K1: Material = Material {
    key: 11,
    roots: 101,
};

/// Source history. Index == revision. The single writer thread publishes the
/// entries in order, so a revision identifies exactly one snapshot; that is an
/// assumption of the model (by construction), not a checked property.
type History = [Snapshot; 3];
const FINAL: u64 = 2;

struct Scenario {
    name: &'static str,
    history: History,
}

static ROTATION_THEN_WITHDRAWAL: Scenario = Scenario {
    name: "rotation_then_withdrawal",
    history: [
        Snapshot {
            revision: 0,
            withdrawn: false,
            material: K0,
        },
        // Rotation replaces the key and the trust bundles in one revision.
        Snapshot {
            revision: 1,
            withdrawn: false,
            material: K1,
        },
        // PermissionDenied keeps the old context but withdraws it.
        Snapshot {
            revision: 2,
            withdrawn: true,
            material: K1,
        },
    ],
};

static WITHDRAWAL_THEN_RECOVERY: Scenario = Scenario {
    name: "withdrawal_then_recovery",
    history: [
        Snapshot {
            revision: 0,
            withdrawn: false,
            material: K0,
        },
        Snapshot {
            revision: 1,
            withdrawn: true,
            material: K0,
        },
        // Byte-identical recovery. That it advances the revision is modelled
        // by construction (`Source::publish` always publishes).
        Snapshot {
            revision: 2,
            withdrawn: false,
            material: K0,
        },
    ],
};

#[test]
fn rotation_then_withdrawal() {
    verify(&ROTATION_THEN_WITHDRAWAL);
}

#[test]
fn withdrawal_then_recovery() {
    verify(&WITHDRAWAL_THEN_RECOVERY);
}

// ---------------------------------------------------------------------------
// Assertions
// ---------------------------------------------------------------------------

/// Safety properties. They must hold for every acquisition at any time,
/// including acquisitions that overlap publication and conversion. Failing
/// closed (`Err`) is always permitted.
fn check_safety(history: &History, acquisition: Acquisition) {
    let Ok((revision, material)) = acquisition.result else {
        return;
    };
    let observation = acquisition.observation;
    let at = history[usize::try_from(revision).unwrap()];
    // S1: material belongs exclusively to the revision it is labelled with.
    assert_eq!(
        material, at.material,
        "S1 violated: revision {revision} carried material {material:?}, expected {:?}",
        at.material
    );
    // S2: a withdrawn revision never yields material, and the acquisition's own
    // source observation was permitted.
    assert!(
        !at.withdrawn && observation.material.is_ok(),
        "S2 violated: revision {revision} yielded material while withdrawn \
         (observation {observation:?})"
    );
    // S3: the material was converted from exactly the revision the acquisition
    // observed. `observation` is what the source returned, not what the gate was
    // given. It is read inside the acquisition and revisions never decrease, so
    // an acquisition that starts after revision N is published never uses N-1
    // or older.
    assert_eq!(
        revision, observation.revision,
        "S3 violated: acquisition observed source revision {} but used revision {revision}",
        observation.revision
    );
}

/// Quiescent availability (Q1). Checked once, after every thread has joined.
/// It is not a safety property: during publication `Err` is always allowed.
fn check_quiescent(history: &History, acquisition: Acquisition) {
    let last = history[usize::try_from(FINAL).unwrap()];
    let expected = if last.withdrawn {
        Err(AcquireError::Withdrawn)
    } else {
        Ok((last.revision, last.material))
    };
    assert_eq!(
        acquisition.result, expected,
        "Q1 violated: quiescent acquisition must reflect final revision {FINAL}"
    );
}

// ---------------------------------------------------------------------------
// Model
// ---------------------------------------------------------------------------

/// Loom thread ids follow spawn order. Lost-notification detection relies on
/// them (see `Expected::LostNotification`).
fn model(scenario: &'static Scenario, iterations: std::sync::Arc<AtomicUsize>) -> impl Fn() {
    move || {
        iterations.fetch_add(1, Ordering::Relaxed);
        let history = &scenario.history;
        let source = Arc::new(Source::new(history[0]));

        // Thread 1: the supervisor, the only writer.
        let writer = {
            let source = Arc::clone(&source);
            thread::spawn(move || {
                for next in &history[1..] {
                    source.publish(next.withdrawn, next.material);
                }
            })
        };

        // Thread 0 (builder): synchronous prefix of spawn_watching, racing the
        // supervisor. A TlsStatus exists only after it returns.
        let start = watcher_start(&source);
        let applied = Arc::new(start.applied);
        let mut subscription = start.subscription;
        let mut converted = start.initial_revision;

        // Thread 2: watcher task. It stops once it has converted the final
        // revision. A lost notification leaves it blocked forever (Q2).
        let watcher = {
            let source = Arc::clone(&source);
            let applied = Arc::clone(&applied);
            thread::spawn(move || {
                while converted != FINAL {
                    converted = watcher_step(&source, &applied, &mut subscription);
                }
            })
        };

        // Thread 3: a TLS callback acquiring twice, overlapping everything.
        let acquirer = {
            let source = Arc::clone(&source);
            let applied = Arc::clone(&applied);
            thread::spawn(move || {
                for _ in 0..2 {
                    check_safety(history, acquire(&source, &applied));
                }
            })
        };

        writer.join().unwrap();
        watcher.join().unwrap();
        acquirer.join().unwrap();

        // Quiescent: every publication and conversion happens-before this.
        let last = acquire(&source, &applied);
        check_safety(history, last);
        check_quiescent(history, last);
    }
}

// ---------------------------------------------------------------------------
// Expected outcomes
// ---------------------------------------------------------------------------

/// Canonical preemption bound. Exact interleaving counts are enforced only here.
const CANONICAL_PREEMPTION_BOUND: usize = 3;

#[derive(Clone, Copy, Debug)]
enum Expected {
    /// Exploration completes. `iterations` is the exact count at the canonical
    /// bound with the pinned Loom version; any drift fails the test.
    Complete { iterations: usize },
    /// A safety or quiescent assertion fails with this message prefix.
    Violation(&'static str),
    /// Loom deadlock with the writer (1) finished and the watcher (2) blocked
    /// forever: a notification was lost.
    LostNotification,
}

fn expected(scenario: &Scenario) -> Expected {
    let rotation = scenario.name == ROTATION_THEN_WITHDRAWAL.name;
    match VARIANT {
        "baseline" => Expected::Complete { iterations: 26_442 },
        "variant-source-first" => Expected::Complete { iterations: 26_257 },
        "variant-torn-revision-first" => Expected::Complete { iterations: 40_811 },
        "defect-torn-observe" if rotation => Expected::Violation("S1 violated"),
        "defect-torn-observe" => Expected::Violation("Q1 violated"),
        "defect-no-revision-gate" | "defect-gate-applied-revision" => {
            Expected::Violation("S3 violated")
        }
        "defect-notify-before-store" | "defect-observe-before-subscribe" => {
            Expected::LostNotification
        }
        other => panic!("no expected outcome for variant {other}"),
    }
}

fn matches_expected(expected: Expected, message: &str) -> bool {
    match expected {
        Expected::Complete { .. } => false,
        Expected::Violation(prefix) => message.contains(prefix),
        Expected::LostNotification => {
            message.starts_with("deadlock; threads = ")
                && message.contains("(Id(1), Terminated)")
                && message.contains("(Id(2), Blocked(")
        }
    }
}

// ---------------------------------------------------------------------------
// Harness
// ---------------------------------------------------------------------------

/// Exploration settings. `Builder::new()` reads `LOOM_*` variables; every field
/// that affects exploration is overwritten so inherited settings cannot weaken
/// or truncate a run. Only `log` and `location` (diagnostics) are inherited.
fn builder(preemption_bound: usize) -> loom::model::Builder {
    let mut builder = loom::model::Builder::new();
    builder.preemption_bound = Some(preemption_bound);
    // Loom stops silently and reports success when either limit is reached.
    builder.max_permutations = None;
    builder.max_duration = None;
    // A stale checkpoint file would resume a partial exploration.
    builder.checkpoint_file = None;
    builder.checkpoint_interval = 20_000;
    // Loom defaults. Exceeding either panics, which never counts as success.
    builder.max_branches = 1_000;
    builder.max_threads = 5;
    builder.expect_explicit_explore = false;
    builder
}

fn env_usize(name: &str, default: usize) -> usize {
    match std::env::var(name) {
        Ok(value) => value
            .parse()
            .unwrap_or_else(|_| panic!("invalid {name}={value:?}")),
        Err(std::env::VarError::NotPresent) => default,
        Err(err) => panic!("invalid {name}: {err}"),
    }
}

/// Aborts the process if a scenario exceeds its wall-clock budget. An abort is
/// abnormal termination, which `cargo test` always reports as failure.
struct Watchdog {
    _cancel: mpsc::Sender<()>,
}

impl Watchdog {
    fn start(label: String, budget: Duration) -> Self {
        let (cancel, cancelled) = mpsc::channel::<()>();
        std::thread::spawn(move || {
            if let Err(mpsc::RecvTimeoutError::Timeout) = cancelled.recv_timeout(budget) {
                eprintln!("loom-model TIMEOUT: {label} exceeded {budget:?}; aborting");
                std::process::abort();
            }
        });
        Self { _cancel: cancel }
    }
}

fn panic_message(payload: &(dyn std::any::Any + Send)) -> &str {
    if let Some(message) = payload.downcast_ref::<String>() {
        message
    } else if let Some(message) = payload.downcast_ref::<&str>() {
        message
    } else {
        "<non-string panic payload>"
    }
}

fn verify(scenario: &'static Scenario) {
    let bound = env_usize("SPIFFE_LOOM_PREEMPTION_BOUND", CANONICAL_PREEMPTION_BOUND);
    let budget =
        Duration::from_secs(u64::try_from(env_usize("SPIFFE_LOOM_TIMEOUT_SECS", 120)).unwrap());
    let label = format!("{} [{VARIANT}, preemption bound {bound}]", scenario.name);
    let expected = expected(scenario);

    let _watchdog = Watchdog::start(label.clone(), budget);
    let iterations = std::sync::Arc::new(AtomicUsize::new(0));
    let started = Instant::now();
    let outcome = panic::catch_unwind(AssertUnwindSafe(|| {
        // `Builder::check` installs no subscriber, so `LOOM_LOG` needs the one
        // `loom::model` would install. Loom runs its threads on this OS thread,
        // so a thread-local default sees all of them.
        let _log = fmt()
            .with_env_filter(EnvFilter::from_env("LOOM_LOG"))
            .with_test_writer()
            .without_time()
            .finish()
            .set_default();
        builder(bound).check(model(scenario, std::sync::Arc::clone(&iterations)));
    }));
    let explored = iterations.load(Ordering::Relaxed);
    let elapsed = started.elapsed();

    match (expected, outcome) {
        (
            Expected::Complete {
                iterations: canonical,
            },
            Ok(()),
        ) => {
            eprintln!(
                "loom-model PASS: {label}: {explored} interleavings, complete, {} ms",
                elapsed.as_millis()
            );
            if bound == CANONICAL_PREEMPTION_BOUND {
                assert_eq!(
                    explored, canonical,
                    "{label}: interleaving count changed; update the canonical count \
                     only for a reviewed model change"
                );
            }
        }
        (Expected::Complete { .. }, Err(payload)) => panic!(
            "{label}: UNEXPECTED FAILURE after {explored} interleavings: {}",
            panic_message(payload.as_ref())
        ),
        (_, Ok(())) => panic!(
            "{label}: MUTATION NOT DETECTED: expected {expected:?}, but all \
             {explored} interleavings passed"
        ),
        (_, Err(payload)) => {
            let message = panic_message(payload.as_ref());
            assert!(
                matches_expected(expected, message),
                "{label}: DETECTED FOR THE WRONG REASON: expected {expected:?}, got: {message}"
            );
            eprintln!(
                "loom-model DETECTED: {label}: {expected:?} at interleaving {explored}, {} ms",
                elapsed.as_millis()
            );
        }
    }
}
