# Workload API source startup policy

`X509SourceBuilder::build()` and `JwtSourceBuilder::build()` wait for accepted
initial material before publishing a source or spawning its supervisor. The
following policy also applies to their default constructors.

Two phases have different policies. **Initial acquisition** is the work done by
`build()`: it either returns a ready source or an error, and no supervisor exists
until it succeeds. **Steady-state recovery** is the supervisor's work after
`build()` returns `Ok`: it reconnects indefinitely and never returns an error to
the caller. The "During construction" column below describes initial acquisition;
"After readiness" describes steady-state recovery.

Readiness means different things for the two sources:

- `X509Source` is ready when it holds an accepted X.509 context with a selected,
  unexpired SVID. Readiness implies an identity.
- `JwtSource` is ready when it holds an accepted JWT bundle set from
  `FetchJWTBundles`. Readiness implies trust bundles only. JWT-SVIDs are fetched on
  demand by `fetch_jwt_svid`, which can still fail after `build()` returns `Ok`.
  For example, a SPIRE agent configured with `allow_unauthenticated_verifiers = true`
  serves bundles to workloads that have no registration entry, so an unregistered
  workload can build a `JwtSource` and then receive `FetchJwtSvid(NoIdentityIssued)`
  or `FetchJwtSvid(PermissionDenied(_))`. Applications that need to issue JWT-SVIDs
  should fetch one at startup.

| Failure | During construction | After readiness |
| --- | --- | --- |
| Invalid explicit `.endpoint(...)` URI | Return `Source(Endpoint(_))` before transport work | The fixed endpoint is already parsed |
| `SPIFFE_ENDPOINT_SOCKET` unset, not Unicode, or not a valid endpoint URI (default setup) | Return `Source(MissingEndpointSocket)`, `Source(NotUnicodeEndpointSocket(_))` or `Source(Endpoint(_))` before transport work | The endpoint was resolved once by `build()`; later changes to the variable are not read |
| `InvalidArgument` from the client factory or required material stream RPC | Return the `Source` error without retry | Reconnect with backoff. Snapshot and permission are unchanged |
| `Unimplemented` from the required material stream RPC | Return `UnsupportedRpc` with the original cause, without retry | Reconnect with backoff. Snapshot and permission are unchanged |
| `Unimplemented` from the client factory | Retry with backoff | Reconnect with backoff. Snapshot and permission are unchanged |
| `Unavailable`, refused connection, absent Unix socket, interrupted HTTP/2 handshake | Retry with backoff | Retry and retain accepted material |
| `PermissionDenied`, `NoIdentityIssued` from the material stream RPC | Retry while provisioning or authorization can recover | Withdraw the affected material, notify, and retry until a valid complete response reauthorizes it |
| `DeadlineExceeded`, `Unauthenticated`, `Internal`, `Unknown`, `Cancelled` | Retry with backoff | Retry with backoff |
| Malformed or over-limit response | Reject atomically and retry | Reject the update without withdrawing material |
| Other custom factory errors, including endpoint errors returned by the factory | Retry with backoff, including repeated identical errors | Retry with backoff |
| `initial_sync_timeout(...)` elapsed while retrying or while an attempt is pending | Return `InitialSyncTimeout { last_error }` | Not applicable: the deadline bounds construction only |

The required monitored methods are `/SpiffeWorkloadAPI/FetchX509SVID` for X.509 and
`/SpiffeWorkloadAPI/FetchJWTBundles` for JWT bundles. `UnsupportedRpc` covers errors
at RPC establishment/response headers and response trailers before the first
accepted item, including reconnects within initial synchronization. Its cause is
the original `WorkloadApiError::Transport` status, preserving code, message, and
the diagnostic source. A factory's `Unimplemented` has no demonstrated relationship
to the required RPC and does not produce `UnsupportedRpc`.

Fixed endpoints use the existing SPIFFE `Endpoint::parse` grammar: Unix absolute
socket URIs or TCP IP-address/port URIs, without user info, query, or fragment.
The builder validates during its fallible `build()` call and stores a parsed
endpoint in the built-in factory. No identical parsing is repeated on reconnect.
The last `endpoint()` or `client_factory()` setter wins. Builder Debug and endpoint
validation errors do not echo endpoint credentials. Custom factory futures remain
opaque: they are called on every attempt and their errors are retried.

When neither setter is used, `build()` reads and parses `SPIFFE_ENDPOINT_SOCKET`
once, before any connection attempt, with the same grammar. A missing, non-Unicode
or malformed value is an endpoint configuration error: it is returned on the first
poll, without retries or metrics, because backoff cannot correct it. A valid value
whose agent or socket is not yet available is a temporary infrastructure failure
and is retried like a fixed endpoint. The resolved endpoint is reused for the life
of the source: initial attempts, steady-state reconnects, and `JwtSource`'s lazily
created JWT-SVID client all connect to it, and later changes to the variable are not
read. This matches go-spiffe and java-spiffe, which also resolve the address once.
`WorkloadApiClient::connect_env()` is unchanged and still reads the variable on each
call.

Failing startup on `Unimplemented` is a library policy for a required operation,
not proof that every deployment will keep returning it forever. A temporarily
disabled profile or rolling deployment that returns it before readiness now
requires a fresh build attempt after the service is corrected. Unsupported
profiles on older SPIRE versions and custom implementations fail with useful
diagnostics instead of silently waiting.

After readiness, `InvalidArgument` and `Unimplemented` trigger reconnection
with backoff and leave the snapshot and its permission unchanged. Existing
withdrawals and normal usability checks, including expiry where applicable,
still apply. The supervisor stays running, and source health continues to
describe material usability and supervisor liveness. TLS terminal closure
policies and established connection lifetimes are unchanged. Retrying
`InvalidArgument` after readiness is a deliberate availability exception. [SPIFFE Workload Endpoint §6](https://github.com/spiffe/spiffe/blob/88f6cddc4a6ab7998d9664f692fced0290d18f53/standards/SPIFFE_Workload_Endpoint.md#6-error-codes)

## Bounding and cancelling startup

By default `build()` has no deadline and no retry-count limit. It waits
indefinitely, including for a workload that is not registered, which SPIRE reports
as `NoIdentityIssued` and the source retries.

`initial_sync_timeout(...)` is a single deadline around the whole initial
acquisition: client creation, stream connection, the first response, and the
backoff sleeps between attempts. On timeout `build()` returns
`InitialSyncTimeout { last_error }`. Terminal failures never wait for it.

Each wake-up advances the sync before checking the deadline, so the deadline is
not a hard cutoff. If the task is polled late, for example on a busy runtime, that
poll can still complete `build()` with a source or a terminal error, or record a
newer recoverable failure before the timeout is returned.

`last_error` is the most recent recoverable failure observed before the timeout was
returned, which may be after the deadline. It is `None` if no attempt had failed by
then. It is a retrospective diagnostic, not the definitive cause of the timeout: a
later attempt may have been pending for a different reason, or none, when the
timeout was returned. The error is
also the timeout's `source()`, and its `Display` includes the cause, for example
`initial synchronization timed out; last error: x509 source error: no identity
issued`. The cause is reported exactly as the underlying error reports itself,
including any status message sent by the server; no endpoint credentials or key
material are added.

Wrapping `build()` in `tokio::time::timeout` cancels construction in the same way
but yields `Elapsed`, without a cause. Prefer `initial_sync_timeout`.

Dropping the `build()` future, for example in `tokio::select!` or by aborting its
task, is cancellation-safe. No source supervisor exists before accepted initial
material, and source-owned work (client creation, the stream, and backoff timers)
is dropped with the future. This does not guarantee the immediate termination of
dependency-owned transport workers, such as connection tasks spawned by the gRPC
stack, or of tasks spawned by custom factories. The existing cancellation-aware
supervisor setup, shared shutdown join ownership, and pre-first-poll closure guard
are unchanged.

## Application-managed retries

The source's retry classification is fixed: the classes in the table above are
retried or returned regardless of `last_error`. `last_error` does not make a
recoverable class terminal, and it is only available once a deadline has elapsed,
not when the failure first occurs. An application that wants its own policy, such
as giving up on a workload that stays unregistered, can loop over `build()` with a
per-attempt `initial_sync_timeout` and decide from `last_error`. Return at once on
any other error variant, which is already terminal. Each attempt consumes the
builder, so build a new one. The `x509_source` module documentation has a
compiled example.

This bounds how long an unregistered workload waits. It does not reproduce a
policy that fails on the first occurrence of a selected status: each decision is
made only after a full attempt window has elapsed, from the last failure observed
in it.

## Preliminary probes

`WorkloadApiClient::fetch_x509_context()` is a one-shot request, not a readiness
check for a source. It skips source admission (the SVID picker, expiry, and
resource limits), opens an additional `FetchX509SVID` stream, and its result can be
stale by the time `build()` runs. A successful probe followed by an unbounded
`build()` can still wait indefinitely. If you probe, also set
`initial_sync_timeout`.

## Kubernetes

Registration entries may be created after the pod starts, so `NoIdentityIssued`
during startup is expected and retried. Either run `build()` in a task and report
not-ready until it returns, or block on `build()` with `initial_sync_timeout` and
exit non-zero on `InitialSyncTimeout`, so the restart policy and its backoff apply.
Do not treat `is_healthy() == false` immediately after `Ok` as a startup failure:
health also reflects supervisor liveness, which can lag construction briefly.

Startup classification follows the endpoint guidance for unsupported
operations, availability, and provisioning. [SPIFFE Workload Endpoint Appendix A](https://github.com/spiffe/spiffe/blob/f97c46dfd0ff0d4e412cce5c73846a9ca32a99a2/standards/SPIFFE_Workload_Endpoint.md#appendix-a-list-of-error-codes)

Authoritative withdrawal follows the Workload API. [SPIFFE Workload API](https://github.com/spiffe/spiffe/blob/f97c46dfd0ff0d4e412cce5c73846a9ca32a99a2/standards/SPIFFE_Workload_API.md)
