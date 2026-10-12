# Security model

This document describes the security boundaries and invariants implemented by
`rust-spiffe`. It is a guide for maintainers and users, not a formal proof,
certification, or claim that the project has been independently audited.

## Assets and trust boundaries

The protected assets are workload identities, private SVID key material, JWT
tokens, trust bundles, authorization decisions, and the freshness and
trust-domain association of cached identity material.

The main trust boundaries are:

- application code calling these crates;
- the local SPIFFE Workload API endpoint and the protobuf messages it returns;
- certificates, JWTs, and bundle data received from peers or APIs;
- the operating system transport used to reach the Workload API;
- the external parsing and cryptographic implementations used by the crates;
- the SPIFFE/SPIRE operator configuration that decides which identities and
  bundles a workload is entitled to receive.

Network peer input and decoded Workload API messages are treated as potentially
malformed. Material obtained from an authenticated local Workload API is trusted
for issuance and validation decisions only after the library's structural checks
succeed. A compromised workload agent, process, operating system, or configured
trust anchor is outside the protection this library can provide.

## Security invariants

### SPIFFE IDs and trust domains

- A `SpiffeId` has the `spiffe` scheme, a non-empty trust domain, and only the
  trust-domain and path characters permitted by the
  [SPIFFE ID specification](https://github.com/spiffe/spiffe/blob/main/standards/SPIFFE-ID.md#2-spiffe-identity).
- Empty, dot, and trailing-slash path segments are rejected. URI query and
  fragment components are not accepted as identity path data.
- Trust domains are compared and stored in lowercase canonical form; path case
  is preserved and remains significant.
- Trust domains are limited to 255 bytes. `SpiffeId::from_segments` does not
  generate IDs over 2048 bytes; parsing continues to accept longer otherwise
  valid IDs, as the specification requires support for at least 2048 bytes but
  does not define a mandatory parsing maximum.

### X.509-SVIDs and bundles

- An X.509-SVID leaf must contain exactly one URI SAN entry, and that URI must be
  a valid SPIFFE ID with a non-root path. These constraints implement the
  [X.509-SVID certificate profile](https://github.com/spiffe/spiffe/blob/main/standards/X509-SVID.md#3-spiffe-certificate-profile).
- Leaf certificates that are CA/signing-capable, lack `digitalSignature`, or
  have malformed required extensions are rejected. Intermediates must be CA
  certificates with `keyCertSign`.
- A parsed SVID chain is non-empty and bounded in certificate count. Every DER
  object and PKCS#8 private key must parse completely; trailing bytes are not
  silently accepted as part of a single certificate.
- `X509Svid::parse_from_der` checks the SPIFFE certificate profile, but does not
  by itself establish chain trust, verify certificate signatures, prove that the
  private key matches the leaf, or reject a certificate solely because its
  validity window is not current. Callers must use a validating consumer such as
  the rustls integration when authenticating a peer.
- X.509 bundles remain associated with an explicit `TrustDomain`. Bundle parsing
  validates certificate encoding; cryptographic path validation is performed by
  the TLS verifier against the bundle selected for the presented SPIFFE ID's
  trust domain.

### JWT-SVIDs and JWT bundles

- JWT-SVID parsing requires the `sub`, `aud`, and `exp` claims, a supported
  asymmetric JWT-SVID algorithm, and the library's documented `kid` policy.
  The `sub` claim must parse as a SPIFFE ID and `aud` must contain at least one
  value. These checks follow
  [JWT-SVID sections 3 and 4](https://github.com/spiffe/spiffe/blob/main/standards/JWT-SVID.md#3-jwt-svid-token).
- `JwtSvid::parse_insecure` and `from_workload_api_token` perform structural
  parsing only. They must not be used to authenticate an untrusted token.
- `JwtSvid::parse_and_validate` selects the JWT bundle from the subject SPIFFE
  ID's trust domain, selects the authority by `kid`, restricts the algorithm,
  verifies the signature, requires an expected audience, and rejects expired
  tokens. A missing trust-domain bundle or signing key fails closed.
- Offline verification permits only `alg`, required `kid`, and optional `typ`
  in the JOSE header. Present `typ` must be the string `JWT` or `JOSE`. Null,
  duplicate fields, and every additional header parameter (including `crit`,
  `b64`, and key references) reject. Parse-only APIs retain their permissive
  optional-header handling.
- Offline temporal validation uses one `SystemTime` observation at nanosecond
  precision with zero clock skew: `now < exp` and, when present, `now >= nbf`.
  Equality with expiration rejects; equality with activation accepts, as defined
  by [RFC 7519 sections 4.1.4–4.1.5](https://www.rfc-editor.org/rfc/rfc7519.html#section-4.1.4).
  `exp` remains required integer seconds. A present `nbf` must be a JSON number
  exactly representable as nanoseconds in years -9999 through 9999; negative
  dates, decimals, and exponent notation are supported. Nonzero sub-nanosecond
  precision, exponents outside the signed 32-bit range, and out-of-range dates
  reject. A pre-epoch or out-of-range verification clock fails closed.
  jsonwebtoken still verifies the signature, required expiration presence, and
  audience; its temporal checks are disabled to avoid a second clock and rounding.
- Offline validation does not validate `iat` or `iss`. Additional private claims
  remain permitted. Applications must agree on their semantics before using them
  as authorization facts. Workload API token parsing adds no local temporal policy.
- Workload API JWKS input is a purpose-specific JWT bundle. JWKs must have a
  `kid`; cryptographic key validity is checked by the verification backend when
  the key is used.
- After exact domain/`kid` selection, offline verification enforces explicit JWK
  `alg`, `use`, and `key_ops` restrictions. `alg` must match the token; `use`
  must be `sig` or `jwt-svid`; operations must be distinct strings and include
  `verify`. Known encryption/derivation operations cannot accompany an explicit
  signature purpose. Other operations, including extensions, remain supported
  alongside `verify`. EC curve labels and coordinate widths must agree with
  ES256/P-256 or ES384/P-384; backend point/signature checks remain authoritative.
- RSA verification authorities require canonical unpadded Base64urlUInt `n/e`
  without leading zero octets and an actual modulus of at least 2048 bits.
  Both backends share this floor, while their locked upper capacity differs:
  RustCrypto permits up to 4096 bits, AWS-LC up to 8192 bits.
- Optional JWK `alg/use/key_ops` omissions remain supported. RSA keys without
  `alg` are not bound to one algorithm under RFC 8725; explicit trusted `alg`
  metadata is necessary to obtain that restriction. General JWK storage is not
  a verification guarantee and remains permissive. Duplicate JSON fields still
  normalize to their last value; duplicate `kid` insertion still replaces the
  previous authority. No failed authority is rescued by another key or domain.

### Workload API responses and rotation

- Protobuf decoding does not make response contents valid. Certificate, key,
  SPIFFE ID, JWT, and bundle fields are parsed through the same validating types
  used by direct callers. Missing required local X.509 bundle bytes reject the
  complete response.
- Streaming responses represent complete current state. Parsing and resource
  limits are validated before atomic publication; malformed or over-limit
  responses do not partially replace SVIDs or bundles. Valid complete X.509
  responses replace trust even when selection fails or the selected SVID is
  expired. Selection and bundles share one authoritative revision; a configured
  picker never falls back to an old or default identity.
- `PermissionDenied` and `NoIdentityIssued` on a monitored material RPC withdraw
  only that RPC's material, including at stream establishment and reconnect.
  Only a valid complete response reauthorizes it; byte-identical recovery advances
  the revision and notifies consumers. EOF, `Unavailable`, malformed updates,
  and transport recovery alone do not change permission. Independent JWT issuance
  success or failure cannot alter the bundle stream's permission.
- Source health and coalescing update notifications distinguish initial readiness,
  unchanged re-delivery, rotation, withdrawal/recovery, and terminal closure.
  Immutable source observations expose revision, permission, usability, and final
  material independently of terminal status. Previously acquired credentials are
  caller-owned; reacquire a source observation for current authorization.
- Source freshness is operational as well as cryptographic: callers should use
  source health/update APIs and must not assume a cached value remains current
  after shutdown or a prolonged endpoint failure.

### TLS peer verification and authorization

- The peer SPIFFE ID is extracted from the leaf URI SAN and its trust domain is
  used only to select the corresponding bundle.
- rustls performs certificate path, signature, and validity-time verification
  using that trust-domain bundle. DNS/IP hostname validation is intentionally
  not used for SPIFFE authentication.
- SPIFFE leaf constraints are checked in addition to the cryptographic chain.
  Authorization runs only after chain validation succeeds, and an authorizer
  mismatch fails the handshake.
- No bundle from another trust domain is used as a fallback. Missing material,
  malformed identities, lock/cache failures that prevent safe validation, and
  unsupported algorithms fail closed.

- Both resolvers and verifiers load converted TLS material first and then acquire
  the coherent atomic source snapshot. That source load is the material acquisition
  linearization point. An acquisition after publication of revision N cannot use
  converted revision N-1, even while the existing watcher is stalled. Each
  converted revision is Ready or Blocked; conversion failure replaces old Ready
  material with Blocked, and verifier caches cannot bypass the availability check.
- Terminal source or TLS watcher closure has an explicit `TerminalSourcePolicy`.
  `RetainFinal` (compatibility default) permits only the final permitted,
  successfully converted, usable revision. `FailClosed` denies new acquisitions
  when refresh ends. Neither policy restores withdrawal, pending revisions, or
  conversion failures. Temporary transport outages are not terminal closure.
- Existing connections and material acquisitions preceding publication are not
  retroactively reauthorized or revoked. Session resumption remains disabled by
  default. Customizers that re-enable resumption or replace security callbacks
  can bypass new certificate verification and own those resulting guarantees.

## Assumptions and non-goals

- The Workload API transport and endpoint permissions are configured so an
  unauthorized local process cannot impersonate the workload agent.
- Operators provision correct trust bundles and protect SVID private keys after
  delivery. The library cannot recover from a compromised trust anchor, agent,
  workload process, or host.
- Availability against unlimited input at every low-level parsing API is not
  guaranteed. Source builders provide resource limits for long-lived streaming
  use; callers of low-level bundle APIs must also bound input at their boundary.
- Application authorization policy, SPIRE registration correctness, revocation
  policy outside delivered bundle rotation, and secure storage outside the
  library's owned values are application/operator responsibilities.
- The project does not implement cryptographic primitives. It consumes rustls,
  its configured crypto provider, `jsonwebtoken`, and Rust parsing/encoding
  libraries. Their correctness and platform support are dependencies of this
  security model.

The normative references are the SPIFFE
[ID](https://github.com/spiffe/spiffe/blob/main/standards/SPIFFE-ID.md),
[X.509-SVID](https://github.com/spiffe/spiffe/blob/main/standards/X509-SVID.md),
[JWT-SVID](https://github.com/spiffe/spiffe/blob/main/standards/JWT-SVID.md),
[Trust Domain and Bundle](https://github.com/spiffe/spiffe/blob/main/standards/SPIFFE_Trust_Domain_and_Bundle.md),
and [Workload API](https://github.com/spiffe/spiffe/blob/f97c46dfd0ff0d4e412cce5c73846a9ca32a99a2/standards/SPIFFE_Workload_API.md)
specifications. Where this implementation deliberately applies a stricter rule,
such as requiring JWT `kid`, the public API documentation calls it out.
