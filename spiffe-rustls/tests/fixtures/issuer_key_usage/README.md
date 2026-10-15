# Issuer KeyUsage synthetic credentials

These are public test credentials, derived deterministically from labels in
`generate.py`. Never use these keys outside tests. Regenerate with Python 3 and
`cryptography` (`python3 generate.py`); neither is a Rust build/test dependency.
Ed25519 keys and signatures produce byte-for-byte reproducible fixtures.

Verification time is **2030-01-01 00:00:00 UTC** (Unix 1893456000). Certificates
are valid from 2025-01-01 through 2035-01-01, except `leaf-expired.der`, which
expires in 2029. No test uses wall time or validity sleeps.

All leaves use the same key (`leaf.pkcs8`) and normally identify
`spiffe://example.org/workload`. Every issuer variant named `issuer-*` has the
same subject and public key. A leaf signature can therefore be checked with
any variant, independently of that variant's KU eligibility or higher path.

| Fixtures                                                      | Property                                                                                          |
|---------------------------------------------------------------|---------------------------------------------------------------------------------------------------|
| `root.der`, `root-b.der`                                      | Independent explicit trust anchors                                                                |
| `issuer-good.der`                                             | Critical KU: keyCertSign + cRLSign                                                                |
| `issuer-key-cert-sign.der`                                    | Critical KU: keyCertSign only                                                                     |
| `issuer-good-noncritical.der`                                 | Noncritical signing-permitted KU                                                                  |
| `issuer-decipher-only.der`                                    | Two-octet KU: keyAgreement, keyCertSign, decipherOnly                                             |
| `issuer-missing.der`                                          | KU absent                                                                                         |
| `issuer-digital-signature.der`, `issuer-crl-sign.der`         | Critical KU without keyCertSign                                                                   |
| `issuer-noncritical.der`                                      | Noncritical digitalSignature-only KU                                                              |
| `issuer-wrong-tag.der`                                        | BOOLEAN instead of BIT STRING                                                                     |
| `issuer-duplicate.der`                                        | Two identical signing-permitted KU extensions; re-signed after injection                          |
| `issuer-trailing.der`                                         | Signing-permitted BIT STRING followed by inner NULL                                               |
| `issuer-truncated.der`, `issuer-empty.der`                    | Truncated or empty BIT STRING                                                                     |
| `issuer-invalid-unused.der`, `issuer-invalid-padding.der`     | Unused count 8 or nonzero padding                                                                 |
| `issuer-nonminimal-bits.der`, `issuer-nonminimal-length.der`  | Trailing zero named bits or nonminimal DER length                                                 |
| `issuer-nonminimal-oid.der`                                   | Noncritical digitalSignature-only KU hidden behind a nonminimal KU OID; re-signed after injection |
| `issuer-undefined-bit.der`                                    | keyCertSign plus an undefined KU bit                                                              |
| `issuer-constructed.der`, `issuer-indefinite.der`             | Constructed tag or indefinite length                                                              |
| `issuer-not-ca.der`, `issuer-wrong-eku.der`                   | Non-CA or codeSigning-only issuer control                                                         |
| `issuer-name-constraints.der`                                 | Excludes DNS name blocked.example                                                                 |
| `issuer-untrusted.der`                                        | Permitted KU, signed by untrusted root-b                                                          |
| `issuer-bad-signature.der`                                    | Restricted KU and deliberately corrupted issuer signature                                         |
| `issuer-cross-restricted.der`, `issuer-cross-good.der`        | Same issuer key cross-signed by upper-a or upper-b                                                |
| `upper-restricted.der`, `upper-good.der`, `upper-pathlen.der` | Restricted upper-a, permitted upper-b, or upper-b with pathLenConstraint=0                        |
| `leaf.der`, `leaf-direct.der`                                 | Issuer-signed or directly root-signed leaf                                                        |
| `leaf-bad-signature.der`, `leaf-expired.der`                  | Corrupted signature or expired leaf                                                               |
| `leaf-invalid-id.der`, `leaf-wrong-domain.der`                | Pathless SPIFFE identity or other.org identity                                                    |
| `leaf-unauthorized.der`                                       | Valid identity outside the protocol tests' exact authorizer                                       |
| `leaf-client-eku.der`, `leaf-server-eku.der`                  | Role-specific EKU controls                                                                        |
| `leaf-blocked-name.der`                                       | SPIFFE identity plus excluded DNS name                                                            |

The peer leaf BasicConstraints controls `leaf-no-basic-constraints.der`, `leaf-ca.der`, and
`leaf-malformed-basic-constraints.der` omit BC, set cA=true, or encode a BOOLEAN
instead of the BC SEQUENCE. Apart from serial numbers and BC, they are equivalent
to `leaf-basic-constraints.der` (including the matching key, issuer, and explicit
serverAuth/clientAuth EKU). The positive control has cA=false.

Tests are in `src/verifier/issuer_key_usage_tests.rs` and its nested
`leaf_basic_constraints_tests.rs` module. Callback cases exercise
both actual SPIFFE verifiers. Protocol cases use those verifiers with fixed
rustls time providers, mandatory client authentication, disabled resumption,
and an in-memory record pump. Successful peers complete both sides of the
handshake and exchange application data in both directions. Rejections are
asserted on the verifier side, before authorization for invalid paths.

TLS 1.3 runs normally. TLS 1.2 is exercised when explicitly enabled with
`--features rustls/tls12`; otherwise that test's body is skipped. Run the
provider lanes in separate processes:

```sh
cargo test --locked -p spiffe-rustls --lib issuer_key_usage_tests --features rustls/tls12
cargo test --locked -p spiffe-rustls --lib issuer_key_usage_tests --no-default-features --features aws-lc-rs,rustls/tls12
```

The original verifier must succeed before issuer filtering. The 101 repeated
bad-signature issuer candidates exhaust webpki's signature budget before the
good alternative can be reached; filtering first would incorrectly rescue
that originally rejected input. This control protects the original acceptance
boundary, as well as the independent signature, validity, path length, EKU,
name-constraint, identity, trust-domain, bundle, and authorization controls.
