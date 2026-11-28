# loom-tests

Models of the TLS material revision gate: `X509Source` publication,
`MaterialWatcher` conversion, and `TlsStatus` acquisition. The protocol, the
invariants, and the places the model diverges from production are in
[`docs/design/concurrency-model-checking.md`](../docs/design/concurrency-model-checking.md).

These tests run an abstract protocol under Loom. Production `X509Source`,
`MaterialWatcher`, `arc_swap`, and Tokio are not executed. `spiffe-loom-models`
is an unpublished crate with its own workspace and `Cargo.lock`, outside the
root workspace and its dependency audits.

## Running

From the repository root:

```bash
make loom
```

CI runs the same target on Rust 1.88. `make loom` checks formatting, runs
Clippy with `-D warnings` for every variant, then runs the scenarios at
preemption bound 3.

Baseline and `variant-*` features have to finish exploration at the canonical
interleaving count. Each `defect-*` feature has to fail for its expected
reason.

One variant, or one scenario:

```bash
cargo test --locked --manifest-path loom-tests/Cargo.toml -- --nocapture
```

```bash
cargo test --locked --manifest-path loom-tests/Cargo.toml --features defect-torn-observe -- --nocapture rotation_then_withdrawal
```

## Bounds

Canonical runs use preemption bound 3. Exact interleaving counts are checked
only at that bound. Bound 4 takes about three minutes for every
variant:

```bash
make loom-test LOOM_PREEMPTION_BOUND=4
```

```bash
SPIFFE_LOOM_PREEMPTION_BOUND=4 cargo test --locked --manifest-path loom-tests/Cargo.toml -- --nocapture
```

| Variable | Default | Meaning |
| --- | --- | --- |
| `SPIFFE_LOOM_PREEMPTION_BOUND` | 3 | Loom preemption bound |
| `SPIFFE_LOOM_TIMEOUT_SECS` | 120 | Per-scenario budget. The process aborts when it is exceeded. `make` passes 300. |

`LOOM_PREEMPTION_BOUND` and `LOOM_TIMEOUT_SECS` change only when set on the
`make` command line. The harness also clears Loom's own exploration settings.
`LOOM_MAX_PREEMPTIONS`, `LOOM_MAX_PERMUTATIONS`, `LOOM_MAX_DURATION`, and
`LOOM_CHECKPOINT_FILE` cannot cut a run short or resume one. In Loom 0.7.3
those limits return success before exploration has finished.

## Failures

A failing test names the variant, the scenario, the bound, and one of
`MUTATION NOT DETECTED`, `DETECTED FOR THE WRONG REASON`, or
`UNEXPECTED FAILURE`. Loom's panic is printed above that line.

`LOOM_LOG` is a `tracing` filter. `info` prints each thread switch and `trace`
adds every Loom operation; `1` selects errors only and prints no trace. With
`trace`, `LOOM_LOCATION=1` adds source locations. Pass `--nocapture`, run one
scenario, and redirect to a file. Every explored interleaving is printed, so
even a defect that fails early enough to finish in seconds can write millions
of lines:

```bash
LOOM_LOG=info cargo test --locked --manifest-path loom-tests/Cargo.toml --features defect-torn-observe -- --nocapture rotation_then_withdrawal > loom-tests/target/loom-trace.log 2>&1
```

Lines carry an `iter{N}` span. The failing execution is the last one, and `N`
matches the interleaving number the harness reports. Checkpoint replay stays
off.

## Dependencies

`loom` is pinned to `=0.7.3`. `generator` stays at 0.8.11 because 0.8.12
requires Rust 1.95 and the MSRV is 1.88. Use `--locked`. `make` does.

From `loom-tests/`:

```bash
cargo update && cargo update -p generator --precise 0.8.11
```

Then run both toolchains:

```bash
make loom CARGO='cargo +1.88.0'
```

A Loom upgrade changes the interleavings that get explored. Review the
canonical counts, and review the limits the harness clears, before accepting
the new lockfile.

## Changing the model

Synchronization steps live in `src/lib.rs`. Each one names the production
function it follows. Keep that function's order and atomicity. Synchronization
that exists only in the model hides the race under test.

Scenarios, assertions, expected outcomes, and exploration settings live in
`tests/tls_revision_gating.rs`.

A new variant needs all of these:

- a feature in `Cargo.toml`;
- a `cfg` branch in `src/lib.rs`, and entries in `ENABLED_VARIANTS` and `VARIANT`;
- an outcome in `expected()`;
- an entry in `LOOM_VARIANTS` in `make/loom.mk`.

A new assertion needs a defect that fails it for the expected reason. Where
that cannot be done, as with S2, say why in the design document.

Change a canonical count only with a reviewed model change. The count catches
an added or removed schedule point. It is a drift canary, not the completeness
argument. The recorded counts match on macOS with Rust 1.88 and stable. CI
repeats the canonical suite on Linux with Rust 1.88.

When a production function in the correspondence table changes, update the
model in the same pull request, or explain there why the model is unaffected.

## Assumptions

`ArcSwap::load_full` and `store` are taken to be linearizable. Tokio `watch`
is taken to wake a subscriber for every `send_replace` that happens after
`subscribe`. The model does not check either crate.

Only the supervisor publishes, so revisions are unique and increase by
construction. A run covers three revisions, two overlapping acquisitions, and
the configured preemption bound.

The model does not check that one observation's revision and material come from
the same snapshot. `variant-torn-revision-first` mixes two snapshots and passes,
because the assertions apply to what acquisition returns.

Left out: terminal policy and source closure, expiry, conversion errors,
several watchers, verifier caches, and `JwtSource`. Production
`spawn_watching` returns an error when the initial conversion fails, and no
`TlsStatus` is created. The model publishes `Blocked` and keeps going.

S2, the withdrawal check, stays in the assertions. No single planted defect
makes it fail: conversion to `Blocked`, the revision gate, and the permission
check each refuse a withdrawn revision on their own.
