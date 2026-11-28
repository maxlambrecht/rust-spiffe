# JWT authority policy fixtures

`authority-policy.json` contains public JWKs and signed JWTs, with no private key
material. The tests reuse these bytes for deterministic policy regressions and
independently verify them with OpenSSL on every run. Negative metadata/encoding
tests change only the trusted JWK; they never edit signed token bytes.

`generate.rs` uses the existing OpenSSL development dependency to generate fresh
EC and RSA keys, sign the exact compact JWS input, and independently verify each
signature before writing the fixtures. ECDSA signatures are converted from DER
to fixed-width `r || s`; PSS uses matching digest/MGF1 and digest-length salt.
The generator asserts the actual RSA modulus size. Private keys stay in memory.

The corpus covers ES256/P-256, ES384/P-384, all six RS/PS algorithms at
1024/1536/2040/2047/2048/3072/4096/5120 bits, and a 2048-bit exponent-3 key.
An 8192-bit key is included for RS256 only. PS512/1024 is omitted because
digest-length PSS salt cannot fit. Required-claim,
audience, domain, key-ID, expiration and wrong-signing-key controls are separately
signed. The wrong-signing-key control intentionally fails against its stored
authority and verifies against the signing key during generation.

Normal tokens expire at Unix timestamp 4294967295 (2106-02-07). The expired
control has `exp=1`; test execution requires a host clock between those dates.
Keys and signatures are randomly generated once; test inputs are fixed until
explicit regeneration. Regeneration changes fixture bytes and should be reviewed.

From the repository root:

```sh
cargo test --offline --locked -p spiffe --no-default-features --features jwt-verify-rust-crypto --test jwt_authority_policy regenerate_authority_policy_fixtures -- --ignored --nocapture
```

Run the ordinary `jwt_authority_policy` integration target separately with each
verification backend after regeneration. Neither backend is used for signing
these fixtures.
