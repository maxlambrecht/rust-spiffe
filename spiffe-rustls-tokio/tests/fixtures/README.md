# Peer identity extraction fixtures

These self-signed certificates exercise URI SAN parsing after the handshake.
Tests inspect the DER only, so signatures and validity dates are immaterial.
Generate each with OpenSSL and discard the private key.

```sh
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -noenc \
  -keyout /dev/null -subj '/CN=peer-identity-test' -days 1 -outform DER \
  -out spiffe-uri.der -addext 'subjectAltName=URI:spiffe://example.org/workload'
```

For `no-san.der`, omit `-addext`. For `non-spiffe-uri.der`, use
`URI:https://example.org/workload`. For `multiple-uri.der`, use
`URI:spiffe://example.org/workload,URI:spiffe://example.org/other`.
