# Workload API source startup policy

`X509SourceBuilder::build()` and `JwtSourceBuilder::build()` wait for accepted
initial material before publishing a source or spawning its supervisor. The
following policy also applies to their default constructors.

| Failure                                                                             | During construction                                                   | After successful synchronization                                                                  |
|-------------------------------------------------------------------------------------|-----------------------------------------------------------------------|---------------------------------------------------------------------------------------------------|
| Invalid explicit `.endpoint(...)` URI                                               | Return the existing endpoint error before transport work              | Cannot occur: the fixed endpoint is already parsed                                                |
| Required material RPC returns `Unimplemented`                                       | Return source-specific `UnsupportedRpc` with the original error cause | Reconnect with backoff; retain current authorization state                                        |
| `InvalidArgument`                                                                   | Existing immediate `Source` error                                     | Existing retry policy                                                                             |
| `Unavailable`, refused connection, absent Unix socket, interrupted HTTP/2 handshake | Retry with backoff                                                    | Retry; retain accepted material                                                                   |
| `PermissionDenied`, `NoIdentityIssued`                                              | Retry while provisioning/authorization can recover                    | Withdraw the affected material, notify, and retry until a valid complete response reauthorizes it |
| `DeadlineExceeded`, `Unauthenticated`, `Internal`, `Unknown`, `Cancelled`           | Existing retry policy                                                 | Existing retry policy                                                                             |
| Malformed or over-limit response                                                    | Existing atomic rejection and retry policy                            | Existing rejection contract; never treat it as endpoint configuration                             |
| Custom factory or environment discovery error                                       | Existing retry policy, including repeated identical errors            | Existing retry policy                                                                             |

The required monitored methods are `/SpiffeWorkloadAPI/FetchX509SVID` for X.509 and
`/SpiffeWorkloadAPI/FetchJWTBundles` for JWT bundles. `UnsupportedRpc` covers errors
at RPC establishment/response headers and response trailers before the first
accepted item, including reconnects within initial synchronization. Its cause is
the original `WorkloadApiError::Transport` status, preserving code, message, and
the diagnostic source. A factory's `Unimplemented` has no demonstrated relationship
to the required RPC and does not produce `UnsupportedRpc`. The pre-existing
`InvalidArgument` classification remains unchanged, including factory errors.

Fixed endpoints use the existing SPIFFE `Endpoint::parse` grammar: Unix absolute
socket URIs or TCP IP-address/port URIs, without user info, query, or fragment.
The builder validates during its fallible `build()` call and stores a parsed
endpoint in the built-in factory. No identical parsing is repeated on reconnect.
The last `endpoint()` or `client_factory()` setter wins. Builder Debug and endpoint
validation errors do not echo endpoint credentials. Environment discovery remains
dynamic and custom factory futures remain opaque.

Failing startup on `Unimplemented` is a library policy for a required operation,
not proof that every deployment will keep returning it forever. A temporarily
disabled profile or rolling deployment that returns it before readiness now
requires a fresh build attempt after the service is corrected. Unsupported
profiles on older SPIRE versions and custom implementations fail with useful
diagnostics instead of silently waiting. Running sources keep retrying to preserve
compatibility with runtime upgrades and reconfiguration.

An `Unimplemented` received by a running source neither withdraws nor reauthorizes
material. It does not change the material revision or trigger terminal closure.
Authorized material remains available according to existing usability checks;
withdrawn material remains unavailable until a valid response arrives. Source
health is not a connectivity/freshness-age guarantee. TLS `RetainFinal`/`FailClosed`
closure policies are not triggered by this status, and established connections
remain application-owned.

No global deadline or retry-count limit is added. `initial_sync_timeout(...)`
continues to bound recoverable construction failures and pending factory futures.
Cancellation or timeout drops constructor-owned work; no source supervisor exists
before accepted initial material. This does not guarantee the immediate termination
of dependency-owned transport workers or tasks spawned by custom factories. The
existing cancellation-aware supervisor setup, shared shutdown join ownership,
and pre-first-poll closure guard are unchanged.

The policy follows the pinned [Workload Endpoint error guidance](https://github.com/spiffe/spiffe/blob/f97c46dfd0ff0d4e412cce5c73846a9ca32a99a2/standards/SPIFFE_Workload_Endpoint.md#appendix-a-list-of-error-codes)
for unsupported operations, availability, and provisioning. Authoritative
withdrawal follows the pinned [Workload API](https://github.com/spiffe/spiffe/blob/f97c46dfd0ff0d4e412cce5c73846a9ca32a99a2/standards/SPIFFE_Workload_API.md).
