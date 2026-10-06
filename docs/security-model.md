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
- Offline validation does not currently validate `iat`, `nbf`, or `iss`, and
  applies no clock-skew leeway. Applications must not treat unvalidated custom
  claims as authorization facts.
- Workload API JWKS input is a purpose-specific JWT bundle. JWKs must have a
  `kid`; cryptographic key validity is checked by the verification backend when
  the key is used.

### Workload API responses and rotation

- Protobuf decoding does not make response contents valid. Certificate, key,
  SPIFFE ID, JWT, and bundle fields are parsed through the same validating types
  used by direct callers. Missing required local X.509 bundle bytes reject the
  complete response.
- Streaming responses represent complete current state. Source updates are
  validated before atomically replacing last-known-good material; rejected
  updates do not partially replace SVIDs or bundles.
- Source health and update notifications distinguish initial synchronization,
  unchanged re-delivery, genuine rotation, shutdown, and rejected material.
  Resource limits bound source-managed bundle and SVID updates.
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
and [Workload API](https://github.com/spiffe/spiffe/blob/main/standards/SPIFFE_Workload_API.md)
specifications. Where this implementation deliberately applies a stricter rule,
such as requiring JWT `kid`, the public API documentation calls it out.
