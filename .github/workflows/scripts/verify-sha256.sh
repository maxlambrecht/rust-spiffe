#!/usr/bin/env bash
set -euo pipefail

if [ "$#" -ne 2 ]; then
  echo "usage: $0 <file> <expected-sha256>" >&2
  exit 2
fi

file="$1"
expected="$2"

case "${expected}" in
  ''|*[!0-9a-fA-F]*)
    echo "invalid expected SHA-256 value" >&2
    exit 2
    ;;
esac

if [ "${#expected}" -ne 64 ]; then
  echo "invalid expected SHA-256 length" >&2
  exit 2
fi

actual="$(sha256sum "${file}" | awk '{print $1}')"
if [ "${actual}" != "${expected}" ]; then
  echo "SHA-256 mismatch for ${file}: expected ${expected}, got ${actual}" >&2
  exit 1
fi
