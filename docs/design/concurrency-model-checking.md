# Concurrency model checking

`X509Source` publishes one snapshot at a time. `MaterialWatcher` turns that
snapshot into rustls material. `TlsStatus::acquire` returns the material only
when it was converted from the revision the source holds at that moment.
[`loom-tests`](../../loom-tests) checks the ordering of those steps with
[Loom](https://github.com/tokio-rs/loom).

Commands are in [`loom-tests/README.md`](../../loom-tests/README.md). The
library's security boundaries are in
[`docs/security-model.md`](../security-model.md).

The tests execute a model of the protocol. A passing run means the mapped
steps still have the order and atomicity described here. It says nothing about
`ArcSwap`, Tokio, or rustls, and it misses any production change the model does
not mirror.

## Publication

### Source snapshots

`X509Source` (`spiffe/src/x509_source/source.rs`) stores one immutable
`X509SourceState`: the X.509 context, the selected SVID, the withdrawal, and a
`u64` revision. The cell is `Inner::snapshot: ArcSwap<X509SourceState>`.

One supervisor task is the only writer. `Inner::apply_update` and
`Inner::withdraw` both do the same four steps:

1. `load_full` the current state.
2. Build the next state with `revision + 1`.
3. `store` that state.
4. `notify_update`: a `Relaxed` `fetch_add` on `update_seq`, then
   `update_tx.send_replace(seq)` on `tokio::sync::watch`.

There is no compare-and-swap. The load-then-store is safe because nothing else
writes. Readers call `X509Source::state()`, which copies one `load_full` and
then records whether the source is closed. `JwtSource` publishes JWT bundles
the same way. Closure is outside this model.

### MaterialWatcher

`MaterialWatcher::spawn_watching` (`spiffe-rustls/src/resolve.rs`) runs its
setup on the caller's thread, before a TLS callback can exist:

1. `source.updated()`.
2. `observe()`, which calls `state()` once.
3. Return `SourceClosed` when the source is already closed.
4. `build_material`. Construction fails when that conversion fails.
5. Publish `MaterialState { source_revision, material }` on a second watch
   channel.

The spawned task then loops:

1. `updates.changed()`.
2. `observe()` again.
3. Convert.
4. `send_replace` the new `MaterialState`.

A failed conversion publishes `Blocked` for that revision and drops the
previous `Ready` material. On source closure the task observes once more,
because the last notification may have coalesced with an earlier one, and then
stops. A drop guard clears `live` and wakes `TlsStatus::changed` waiters.

### Acquisition

`TlsStatus::acquire` loads the applied `MaterialState`, then observes the
source. That observation is the acquisition's linearization point.
`acquire_from` decides:

1. An observation that is withdrawn or otherwise unusable is an error, ahead
   of every other outcome.
2. `observation.revision != applied.source_revision` is `PendingRevision`.
3. After refresh has ended, `TerminalSourcePolicy` applies.
4. Otherwise return the applied material, or `MaterialUnavailable` when it is
   `Blocked`.

TLS therefore uses material converted from the revision the source holds at
the observation, including while the watcher is still behind.

```text
supervisor ─ store(rev N) ─ send_replace ─▶ watch ─▶ watcher: observe, convert, publish(N)
                 │                                                    │
                 ▼                                                    ▼
TLS callback:  observe source (rev)  ◀── compare ──▶  applied MaterialState (rev)
```

## Invariants

| ID | Invariant | What it depends on |
| --- | --- | --- |
| I1 | A revision names exactly one snapshot, and revisions strictly increase | One writer, in program order |
| I2 | Identity, selection, bundles, and permission are published together | One `store` of a finished value |
| I3 | An observation's revision and material come from the same snapshot | One `load_full` per observation |
| I4 | Converted material belongs only to the revision it is labelled with | I3, and labelling with the observed revision |
| I5 | An acquisition that starts after revision N is published never uses material from N-1 or older | A fresh observation, plus the equality gate |
| I6 | A withdrawn revision never yields material | The permission check, `Blocked` conversion, and the gate |
| I7 | Recovery after withdrawal is observable, including a byte-identical update | `apply_update` treats an existing withdrawal as a change |
| I8 | The watcher eventually converts the latest revision | Store before notify; subscribe before the initial observation |

`spiffe` unit and lifecycle tests cover I1, I2, and I7. The Loom model covers
I4–I6 and I8, which depend on interleavings across the two crates. It checks I4
only for material that a successful acquisition returns.

The model does not check I3. Its baseline `observe` copies production's single
`load_full`, and no assertion inspects an observation. Under
`variant-torn-revision-first`, an observation can pair revision 1 with revision
2's withdrawal, and the builder's initial conversion can store `K1` labelled
as revision 0. That variant still passes: the gate never returns the
mislabelled material in these scenarios.

## What runs under Loom

Loom schedules its own mutexes, threads, and atomics. It cannot see
`arc_swap::ArcSwap`. Tokio's `watch` loom tests are inside Tokio's own test
build and are not available here. Tasks, `select!`, timers,
`CancellationToken`, and abort need a Tokio runtime. Driving production
`X509Source` or `MaterialWatcher` under `loom::model` would explore none of
the operations that matter. Instrumenting production with ArcSwap and Tokio
shims is not acceptable in this repository.

Each synchronization step is copied in production's order, with the same
atomicity. Each opaque dependency is replaced with a Loom stand-in that offers
only the guarantee that step relies on.

The crate is separate for practical reasons. A global `RUSTFLAGS="--cfg loom"`
makes Tokio drop `tokio::net`, and hyper-util then fails to compile.
`generator` 0.8.12, pulled in by Loom 0.7.3, requires Rust 1.95, so the
standalone lockfile holds 0.8.11 and the workspace MSRV stays 1.88. Loom's
dependencies stay out of the published crates and out of their audits.

## The model

| Loom thread | Production |
| --- | --- |
| 0 | The builder thread, running `spawn_watching`'s setup while the supervisor runs |
| 1 | The supervisor, the only writer, publishing two revisions |
| 2 | The watcher task, looping until it has converted the final revision |
| 3 | A TLS callback, acquiring twice while the other threads run |

After the three spawned threads have joined, thread 0 acquires once more, in
the quiescent state.

| Scenario | r0 | r1 | r2 |
| --- | --- | --- | --- |
| rotation then withdrawal | `K0` | `K1`, key and bundles together | `K1`, withdrawn |
| withdrawal then recovery | `K0` | `K0`, withdrawn | `K0`, the same bytes, permitted again |

| Model (`loom-tests/src/lib.rs`) | Production |
| --- | --- |
| `Register<T>` | An atomic snapshot. Source state uses `ArcSwap` `load_full` and `store`. Applied `MaterialState` uses `watch::Receiver::borrow` and `Sender::send_replace`. Acquire only needs that snapshot; nothing in the model waits on the material channel. |
| `Watch` | The source `tokio::sync::watch`: `send_replace`, `subscribe`, and `changed` |
| `Snapshot` | `X509SourceState` |
| `Source::publish` | `Inner::apply_update` on the applied path, and `Inner::withdraw` |
| `Source::notify_update` | `Inner::notify_update` |
| `Source::observe` | `<X509Source as X509MaterialSource>::observe` |
| `convert` | `build_material`, reduced to Ready or Blocked |
| `watcher_start` | The synchronous prefix of `MaterialWatcher::spawn_watching` |
| `watcher_step` | One iteration of the watcher task |
| `acquire` / `acquire_from` | `TlsStatus::acquire` / `TlsStatus::acquire_from` |

Taken as given, and not checked:

- `load_full` and `store` are linearizable, and a load returns one whole value
  that was previously stored.
- `send_replace` replaces the value and advances the version together.
  `subscribe` marks the current version as seen. `changed` completes once there
  is an unseen version, even one sent before the call, and marks the latest as
  seen. Several sends can coalesce into one completion, so intermediate
  versions may be skipped.
- Only the supervisor publishes source state.

Some production behavior is simplified on purpose.

`spawn_watching` returns an error when the initial observation is closed or
its conversion fails, and no `TlsStatus` exists afterwards. The model publishes
`Blocked` and continues. In the withdrawal-then-recovery scenario the builder
can observe the withdrawn revision and then keep running, which production
never does. Safety checks still apply: they hold for every interleaving the
model explores, and the production path that aborts construction performs no
acquisitions. Quiescent availability on those interleavings describes the
model. Production reports the construction error to the caller.

`Source::publish` always stores a new revision. `apply_update` skips an
unchanged re-delivery unless the current state is withdrawn, and `withdraw`
ignores a repeated withdrawal.

Conversion is Ready or Blocked. Certificate parsing, conversion errors for
permitted material, expiry, and the watcher's `generation` (the verifier cache
key) are left out. The source never closes, `refreshing` is always true, and
`TerminalSourcePolicy`, the `live` flag, and the final re-read on closure are
absent.

## What is checked

| Property | Kind | Result |
| --- | --- | --- |
| S1. Returned material equals the history entry for the returned revision | Safety, I4 for returned material | Fails under `defect-torn-observe` |
| S2. A returned revision is not withdrawn, and that acquisition's own observation was permitted | Safety, I6 | Runs on every success. No single defect falsifies it; see below |
| S3. The returned revision equals the revision the same acquisition read from the source | Safety, I5 | Fails under `defect-no-revision-gate` and `defect-gate-applied-revision` |
| Q1. After every thread has joined, acquisition matches revision 2: `Err(Withdrawn)`, or `Ok((2, K0))` after recovery | Availability | Fails under `defect-torn-observe` in the recovery scenario |
| Q2. The watcher converts revision 2 | Bounded liveness, I8 | A lost notification is the Loom deadlock from `defect-notify-before-store` and `defect-observe-before-subscribe` |
| I1, revision identity and monotonicity | Input | One writer thread |
| I3, one snapshot per observation | Input | The baseline `observe` loads once; not asserted |
| I7, recovery advances the revision | Input | `publish` always stores |
| ArcSwap and `watch` | Input | Assumed |

Safety is checked on every acquisition. An error is always a permitted
outcome, so S1–S3 apply only when acquisition returns material. Q1 is checked
only after the run has quiesced.

S3 is what gives I5. The observation happens inside the acquisition, revisions
never go backwards, and an acquisition that starts after revision N is stored
observes N or later. S3 requires the returned revision to be that observation.
The harness compares against the observation as `Source::observe` returned it,
not as the gate received it. A gate fed some other revision, such as the applied
material's own, therefore cannot also change the expected value;
`defect-gate-applied-revision` checks this. The recorded observation is a value
the acquisition already read, so the check adds no load, lock, or other schedule
point.

S2 cannot be falsified by removing any one of its three checks. Conversion
turns a withdrawn observation into `Blocked`. The revision gate rejects
material converted from any other revision. Acquisition checks permission
before either of those. With the other two still present, a withdrawn revision
does not come back as `Ok`. S2 stays as an executable assertion so a combined
regression is still caught. There is no planted defect whose only job is to
make S2 fail. The permission check's separate role, winning over terminal
retention of the last good material, sits in the terminal behavior this model
leaves out.

## Mutations

Each Cargo feature compiles one variant. Enabling two is a compile error.

| Variant | Change | Expected outcome |
| --- | --- | --- |
| baseline | none | Exploration finishes |
| `variant-source-first` | `acquire` observes the source before loading applied material | Exploration finishes. The documented order is sufficient for S1–S3; this order also passes |
| `variant-torn-revision-first` | `observe` loads twice, revision first | Exploration finishes. Observations and stored material can mix snapshots, so I3 does not hold, but S1–S3 and Q1 do. Production still uses one load |
| `defect-torn-observe` | `observe` loads twice, material first | Rotation: S1. Recovery: Q1 |
| `defect-no-revision-gate` | The equality gate is removed | S3 in both scenarios |
| `defect-gate-applied-revision` | The gate takes its source revision from the applied material | S3 in both scenarios |
| `defect-notify-before-store` | Notify, then store | Lost notification in both scenarios |
| `defect-observe-before-subscribe` | Observe, then subscribe | Lost notification in both scenarios |

The harness classifies the panic. A nonzero exit status is not the result.

A safety or availability failure has to carry its own assertion text, such as
`S1 violated`. A lost notification has to be a Loom deadlock in which thread 1
(the writer) has terminated and thread 2 (the watcher) is blocked. Anything
else fails the test and says why: a clean run where a defect was required, a
different assertion, a different deadlock, branch exhaustion, a leak, a Loom
panic, or any failure of a variant that should have completed. A watchdog
aborts the process when a scenario exceeds its time budget.

`make loom-test` also requires the Cargo summary for each variant to report
exactly two scenarios run and passed, with none ignored or filtered.

## Exploration

The canonical preemption bound is 3. All five defects show up at that bound.
`defect-torn-observe` in the rotation scenario needs a bound of at least 3.
Bound 4 is available for a slower look.

Loom 0.7.3 `Builder::check` returns normally when it hits `max_permutations`
or `max_duration`. That is a partial exploration reported as success. It also
resumes from a checkpoint file when one is configured. `Builder::new()` reads
those settings from `LOOM_*`.

The harness sets the preemption bound from `SPIFFE_LOOM_PREEMPTION_BOUND`
(default 3), clears both limits, sets no checkpoint file, and sets the
checkpoint interval, branch limit, and thread limit to Loom's defaults.
Inherited environment variables cannot truncate a run, weaken the bound, or
resume from a stale checkpoint.

With those settings, a successful return from the pinned `check` means
exploration finished for that bound. Exceeding the branch limit panics, and
the harness treats that panic as a failure.

At bound 3 the harness also requires an exact interleaving count for each
variant and scenario. The count is there to catch an accidental schedule
point. It is not what makes the exploration complete. The counts match on
macOS with Rust 1.88 and stable. CI runs this suite on Linux with Rust 1.88;
a count that differs there fails the job.

Results cover three revisions, two overlapping acquisitions, and the
configured bound. Longer histories and deeper preemption are still open.
Loom treats `SeqCst` as `AcqRel` and does not explore load buffering. Protocol
state sits behind Loom mutexes, so weak-memory behavior inside ArcSwap and
`watch` is out of scope. Lost-notification classification depends on Loom
thread ids following spawn order.

## Keeping the model honest

A change to a production function in the correspondence table updates the
model in the same pull request, or the pull request says why the model is
unaffected.

A new synchronization step keeps production's order and atomicity. It does
not add a lock, load, or atomic that the production step does not have.

A new checked property comes with a defect that falsifies it for the expected
reason. S2 is the exception already recorded above.

Canonical counts change only with a reviewed model change, and the pull
request says why. When production gains or loses behavior that the model
abstracts, update the differences above.

Production synchronization stays as it is. The model follows it. ArcSwap and
Tokio shims do not belong in the published crates.
