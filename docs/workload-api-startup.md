# Workload API source startup policy

`X509SourceBuilder::build()` and `JwtSourceBuilder::build()` wait for accepted
initial material before publishing a source or spawning its supervisor. The
following policy also applies to their default constructors.

| Failure | During construction | After readiness |
| --- | --- | --- |
| Invalid explicit `.endpoint(...)` URI | Return the endpoint error before transport work | The fixed endpoint is already parsed |
| `InvalidArgument` from the client factory or required material stream RPC | Return the `Source` error without retry | Reconnect with backoff. Snapshot and permission are unchanged |
| `Unimplemented` from the required material stream RPC | Return `UnsupportedRpc` with the original cause, without retry | Reconnect with backoff. Snapshot and permission are unchanged |
| `Unimplemented` from the client factory | Retry with backoff | Reconnect with backoff. Snapshot and permission are unchanged |
| `Unavailable`, refused connection, absent Unix socket, interrupted HTTP/2 handshake | Retry with backoff | Retry and retain accepted material |
| `PermissionDenied`, `NoIdentityIssued` from the material stream RPC | Retry while provisioning or authorization can recover | Withdraw the affected material, notify, and retry until a valid complete response reauthorizes it |
| `DeadlineExceeded`, `Unauthenticated`, `Internal`, `Unknown`, `Cancelled` | Retry with backoff | Retry with backoff |
| Malformed or over-limit response | Reject atomically and retry | Reject the update without withdrawing material |
| Other custom factory or environment discovery errors | Retry with backoff, including repeated identical errors | Retry with backoff |

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
validation errors do not echo endpoint credentials. Environment discovery remains
dynamic and custom factory futures remain opaque.

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

No global deadline or retry-count limit is added. `initial_sync_timeout(...)`
continues to bound recoverable construction failures and pending factory futures.
Cancellation or timeout drops constructor-owned work; no source supervisor exists
before accepted initial material. This does not guarantee the immediate termination
of dependency-owned transport workers or tasks spawned by custom factories. The
existing cancellation-aware supervisor setup, shared shutdown join ownership,
and pre-first-poll closure guard are unchanged.

Startup classification follows the endpoint guidance for unsupported
operations, availability, and provisioning. [SPIFFE Workload Endpoint Appendix A](https://github.com/spiffe/spiffe/blob/f97c46dfd0ff0d4e412cce5c73846a9ca32a99a2/standards/SPIFFE_Workload_Endpoint.md#appendix-a-list-of-error-codes)

Authoritative withdrawal follows the Workload API. [SPIFFE Workload API](https://github.com/spiffe/spiffe/blob/f97c46dfd0ff0d4e412cce5c73846a9ca32a99a2/standards/SPIFFE_Workload_API.md)
