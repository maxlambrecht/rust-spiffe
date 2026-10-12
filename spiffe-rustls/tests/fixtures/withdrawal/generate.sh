#!/bin/sh
# Regenerate public test credentials only. Run from the repository root.
set -eu
out=spiffe-rustls/tests/fixtures/withdrawal
task_tmp=$(mktemp -d)
trap 'rm -rf "$task_tmp"' EXIT HUP INT TERM
for name in a b; do
    openssl ecparam -name prime256v1 -genkey -noout -out "$task_tmp/$name.key"
    openssl pkcs8 -topk8 -nocrypt -in "$task_tmp/$name.key" -outform DER -out "$out/$name.pkcs8"
    openssl ecparam -name prime256v1 -genkey -noout -out "$task_tmp/$name-ca.key"
    openssl req -new -x509 -key "$task_tmp/$name-ca.key" -subj "/CN=Withdrawal test $name" \
        -days 7300 -out "$task_tmp/$name-ca.pem" \
        -addext 'basicConstraints=critical,CA:TRUE' -addext 'keyUsage=critical,keyCertSign,cRLSign'
    openssl x509 -in "$task_tmp/$name-ca.pem" -outform DER -out "$out/$name-ca.der"
done
for name in a b other foreign; do
    signer=b
    identity=example.org/service
    [ "$name" != a ] || signer=a
    [ "$name" != other ] || identity=example.org/other
    [ "$name" != foreign ] || identity=foreign.example/service
    cat > "$task_tmp/leaf.ext" <<EOF
basicConstraints=critical,CA:FALSE
keyUsage=critical,digitalSignature
extendedKeyUsage=clientAuth,serverAuth
subjectAltName=critical,URI:spiffe://$identity,DNS:example.org
EOF
    openssl req -new -key "$task_tmp/$signer.key" -subj / -out "$task_tmp/leaf.csr"
    openssl x509 -req -in "$task_tmp/leaf.csr" -CA "$task_tmp/$signer-ca.pem" \
        -CAkey "$task_tmp/$signer-ca.key" -set_serial "0x$(openssl rand -hex 16)" \
        -days 7300 -extfile "$task_tmp/leaf.ext" -outform DER -out "$out/$name.der"
done
openssl ecparam -name secp256k1 -genkey -noout -out "$task_tmp/unsupported.key"
openssl pkcs8 -topk8 -nocrypt -in "$task_tmp/unsupported.key" -outform DER -out "$out/unsupported.pkcs8"
