# Withdrawal test credentials

These are public test credentials generated with `generate.sh` using OpenSSL.
They are never used outside tests. A and B use independent P-256 CAs and
private keys. A and B identify `spiffe://example.org/service`; `other` identifies
`spiffe://example.org/other`, and `foreign` identifies
`spiffe://foreign.example/service`. Both additional leaves use B's key and CA. All leaves also carry the DNS SAN
`example.org` for the independent rustls peer's standard hostname verification.
The intentionally unsupported key is secp256k1: SPIFFE's PKCS#8 container parser
accepts it, while both supported rustls providers reject TLS key conversion.
Pairing A with B's P-256 key exercises a distinct key mismatch error.

Certificates generated on 2026-10-12 expire in 2046. Tests use the fixed DER
fixtures, not runtime key generation. The expired identity test uses the existing
expired fixture copied from `spiffe/tests/testdata/svid/x509/`. Its key and chain
are kept local here so packaged tests are self-contained; the generator leaves
these expired fixtures unchanged.

Regenerate from the repository root with:

```sh
sh spiffe-rustls/tests/fixtures/withdrawal/generate.sh
```

Regeneration intentionally creates new test keys and certificate serial numbers.
