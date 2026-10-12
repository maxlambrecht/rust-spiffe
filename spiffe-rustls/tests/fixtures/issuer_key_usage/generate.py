"""Regenerate synthetic issuer KeyUsage fixtures: Python 3 + cryptography.

All keys are deterministically derived public test credentials, never secrets.
Certificates are valid 2025-2035; verifier tests evaluate at 2030-01-01 UTC.
Ed25519 signatures make regeneration byte-for-byte reproducible.
"""

from datetime import datetime, timezone
from hashlib import sha256
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.x509.oid import NameOID, ObjectIdentifier

OUT = Path(__file__).resolve().parent
KU = ObjectIdentifier("2.5.29.15")
START = datetime(2025, 1, 1, tzinfo=timezone.utc)
END = datetime(2035, 1, 1, tzinfo=timezone.utc)


def key(label):
    return Ed25519PrivateKey.from_private_bytes(sha256(label.encode()).digest())


def name(label):
    return x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, label)])


def tlv(tag, value):
    length = len(value)
    if length < 128:
        encoded_length = bytes([length])
    else:
        raw = length.to_bytes((length.bit_length() + 7) // 8, "big")
        encoded_length = bytes([0x80 | len(raw)]) + raw
    return bytes([tag]) + encoded_length + value


def split(data):
    """Split a DER sequence's contents for test-only extension mutations."""
    values = []
    while data:
        length = data[1]
        offset = 2
        if length & 0x80:
            count = length & 0x7F
            length = int.from_bytes(data[2:2 + count], "big")
            offset += count
        end = offset + length
        values.append((data[0], data[offset:end], data[:end]))
        data = data[end:]
    return values


def issue(label, subject, subject_key, issuer, issuer_key, *, ca=True,
          ku=b"\x03\x02\x01\x06", critical=True, path_length=None,
          duplicate=False, nonminimal_oid=False, eku=None, uri="spiffe://example.org/workload",
          end=END, constraints=None, dns=None):
    builder = (x509.CertificateBuilder().subject_name(name(subject))
               .issuer_name(name(issuer)).public_key(subject_key.public_key())
               .serial_number(int.from_bytes(sha256(label.encode()).digest()[:16], "big"))
               .not_valid_before(START).not_valid_after(end)
               .add_extension(x509.BasicConstraints(ca, path_length), True))
    if ku is not None:
        builder = builder.add_extension(x509.UnrecognizedExtension(KU, ku), critical)
    if not ca:
        names = [x509.UniformResourceIdentifier(uri)]
        if dns is not None:
            names.append(x509.DNSName(dns))
        builder = builder.add_extension(x509.SubjectAlternativeName(names), False)
    if eku is not None:
        builder = builder.add_extension(x509.ExtendedKeyUsage(
            [ObjectIdentifier(oid) for oid in eku]), False)
    if constraints is not None:
        builder = builder.add_extension(constraints, True)
    cert = builder.sign(issuer_key, None)
    der = cert.public_bytes(serialization.Encoding.DER)
    if duplicate or nonminimal_oid:
        outer = split(split(der)[0][1])
        tbs = split(outer[0][1])
        extensions = split(split(tbs[-1][1])[0][1])
        ku_extension = next(raw for _, value, raw in extensions
                            if value.startswith(b"\x06\x03\x55\x1d\x0f"))
        if nonminimal_oid:
            fields = split(split(ku_extension)[0][1])
            fields[0] = (0x06, b"", tlv(0x06, b"\x55\x1d\x80\x0f"))
            replacement = tlv(0x30, b"".join(raw for _, _, raw in fields))
            encoded_extensions = b"".join(replacement if raw == ku_extension else raw
                                          for _, _, raw in extensions)
        else:
            encoded_extensions = b"".join(raw for _, _, raw in extensions) + ku_extension
        tbs[-1] = (0xA3, b"", tlv(0xA3, tlv(0x30, encoded_extensions)))
        encoded_tbs = tlv(0x30, b"".join(raw for _, _, raw in tbs))
        der = tlv(0x30, encoded_tbs + outer[1][2]
                  + tlv(0x03, b"\x00" + issuer_key.sign(encoded_tbs)))
    (OUT / (label + ".der")).write_bytes(der)


root, root_b, issuer, upper_a, upper_b, leaf = map(key,
    ["issuer-ku-root", "issuer-ku-root-b", "issuer-ku-issuer", "issuer-ku-upper-a",
     "issuer-ku-upper-b", "issuer-ku-leaf"])
issue("root", "root", root, "root", root)
issue("root-b", "root-b", root_b, "root-b", root_b)
variants = {
    "good": b"\x03\x02\x01\x06",
    "key-cert-sign": b"\x03\x02\x02\x04",
    "digital-signature": b"\x03\x02\x07\x80",
    "crl-sign": b"\x03\x02\x01\x02",
    "missing": None,
    "wrong-tag": b"\x01\x01\xff",
    "trailing": b"\x03\x02\x02\x04\x05\x00",
    "truncated": b"\x03\x02\x02",
    "empty": b"\x03\x01\x00",
    "invalid-unused": b"\x03\x03\x08\x04\x00",
    "invalid-padding": b"\x03\x02\x02\x05",
    "nonminimal-bits": b"\x03\x03\x00\x04\x00",
    "nonminimal-length": b"\x03\x81\x02\x02\x04",
    "undefined-bit": b"\x03\x03\x00\x04\x01",
    "constructed": b"\x23\x02\x02\x04",
    "indefinite": b"\x03\x80\x02\x04\x00\x00",
    "decipher-only": b"\x03\x03\x07\x0c\x80",
}
for label, value in variants.items():
    issue("issuer-" + label, "issuer", issuer, "root", root, ku=value)
issue("issuer-noncritical", "issuer", issuer, "root", root,
      ku=variants["digital-signature"], critical=False)
issue("issuer-good-noncritical", "issuer", issuer, "root", root, critical=False)
issue("issuer-duplicate", "issuer", issuer, "root", root, duplicate=True)
issue("issuer-nonminimal-oid", "issuer", issuer, "root", root,
      ku=variants["digital-signature"], critical=False, nonminimal_oid=True)
issue("issuer-not-ca", "issuer", issuer, "root", root, ca=False)
issue("issuer-untrusted", "issuer", issuer, "root-b", root_b)
issue("upper-restricted", "upper-a", upper_a, "root", root,
      ku=variants["digital-signature"])
issue("upper-good", "upper-b", upper_b, "root", root)
issue("upper-pathlen", "upper-b", upper_b, "root", root, path_length=0)
issue("issuer-cross-restricted", "issuer", issuer, "upper-a", upper_a)
issue("issuer-cross-good", "issuer", issuer, "upper-b", upper_b)
issue("issuer-wrong-eku", "issuer", issuer, "root", root,
      eku=["1.3.6.1.5.5.7.3.3"])
issue("issuer-name-constraints", "issuer", issuer, "root", root,
      constraints=x509.NameConstraints(None, [x509.DNSName("blocked.example")]))
leaf_options = dict(ca=False, ku=b"\x03\x02\x07\x80")
issue("leaf", "leaf", leaf, "issuer", issuer, **leaf_options)
issue("leaf-direct", "leaf", leaf, "root", root, **leaf_options)
issue("leaf-expired", "leaf", leaf, "issuer", issuer,
      end=datetime(2029, 1, 1, tzinfo=timezone.utc), **leaf_options)
issue("leaf-invalid-id", "leaf", leaf, "issuer", issuer,
      uri="spiffe://example.org", **leaf_options)
issue("leaf-wrong-domain", "leaf", leaf, "issuer", issuer,
      uri="spiffe://other.org/workload", **leaf_options)
issue("leaf-unauthorized", "leaf", leaf, "issuer", issuer,
      uri="spiffe://example.org/unauthorized", **leaf_options)
issue("leaf-blocked-name", "leaf", leaf, "issuer", issuer,
      dns="blocked.example", **leaf_options)
for role, oid in [("client", "1.3.6.1.5.5.7.3.2"),
                  ("server", "1.3.6.1.5.5.7.3.1")]:
    issue("leaf-" + role + "-eku", "leaf", leaf, "issuer", issuer,
          eku=[oid], **leaf_options)
bad_signature = bytearray((OUT / "leaf.der").read_bytes())
bad_signature[-1] ^= 1
(OUT / "leaf-bad-signature.der").write_bytes(bad_signature)
bad_signature = bytearray((OUT / "issuer-digital-signature.der").read_bytes())
bad_signature[-1] ^= 1
(OUT / "issuer-bad-signature.der").write_bytes(bad_signature)
(OUT / "leaf.pkcs8").write_bytes(leaf.private_bytes(serialization.Encoding.DER,
    serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
