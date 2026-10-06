#!/usr/bin/env bash

# Rechecks the release state recorded by the publish workflow's preflight job.
#
# This runs in the OIDC-capable publish job, so it must not build or execute
# repository or dependency Rust code. `reproduce` may run
# `cargo package --no-verify` to recreate the archive; `final` performs only
# local invariant checks.
#
# Usage:
#   release-recheck.sh reproduce  # before crates.io authentication
#   release-recheck.sh final      # after crates.io authentication: local-only recheck

set -euo pipefail

fail() {
  echo "release recheck failed: $*" >&2
  exit 1
}

for name in RELEASE_TAG RELEASE_CRATE RELEASE_VERSION EXPECTED_COMMIT \
  EXPECTED_LOCK_SHA256 EXPECTED_PACKAGE_SHA256 EXPECTED_CARGO_VERSION; do
  [ -n "${!name:-}" ] || fail "${name} is not set"
done

case "${RELEASE_CRATE}" in
  spiffe | spire-api | spiffe-rustls | spiffe-rustls-tokio) ;;
  *) fail "unexpected release crate '${RELEASE_CRATE}'" ;;
esac

[ "${RELEASE_TAG}" = "${RELEASE_CRATE}-${RELEASE_VERSION}" ] ||
  fail "tag '${RELEASE_TAG}' is not '${RELEASE_CRATE}-${RELEASE_VERSION}'"

git check-ref-format "refs/tags/${RELEASE_TAG}" ||
  fail "invalid tag name '${RELEASE_TAG}'"

export CARGO_TARGET_DIR="${PWD}/target"
package_path="${CARGO_TARGET_DIR}/package/${RELEASE_CRATE}-${RELEASE_VERSION}.crate"

sha256() {
  sha256sum "$1" | awk '{print $1}'
}

expect_eq() { # <what> <actual> <expected>
  [ "$2" = "$3" ] || fail "$1: expected '$3', got '$2'"
}

require_clean_tree() {
  local status submodules

  status="$(git status --porcelain --untracked-files=all)"
  [ -z "${status}" ] || fail "working tree is not clean"

  # Cargo packages initialized submodule files, so they are package inputs.
  submodules="$(git submodule status --recursive)"
  ! printf '%s\n' "${submodules}" | grep -q '^[-+U]' ||
    fail "submodules are not checked out at their committed revisions"
}

check_release_state() {
  expect_eq "checked-out commit" \
    "$(git rev-parse --verify 'HEAD^{commit}')" \
    "${EXPECTED_COMMIT}"

  expect_eq "release tag commit" \
    "$(git rev-parse --verify "refs/tags/${RELEASE_TAG}^{commit}")" \
    "${EXPECTED_COMMIT}"

  expect_eq "current main commit" \
    "$(git rev-parse --verify 'refs/remotes/origin/main^{commit}')" \
    "${EXPECTED_COMMIT}"

  git ls-files --error-unmatch -- Cargo.lock >/dev/null ||
    fail "Cargo.lock is not tracked"

  expect_eq "Cargo.lock SHA-256" \
    "$(sha256 Cargo.lock)" \
    "${EXPECTED_LOCK_SHA256}"

  expect_eq "Cargo version" \
    "$(cargo --version)" \
    "${EXPECTED_CARGO_VERSION}"

  require_clean_tree
}

case "${1:-}" in
  reproduce)
    # Non-forced refspecs: a moved tag or rewritten main fails the fetch.
    git fetch --no-tags origin \
      refs/heads/main:refs/remotes/origin/main \
      "refs/tags/${RELEASE_TAG}:refs/tags/${RELEASE_TAG}"

    check_release_state

    cargo package \
      --locked \
      --no-verify \
      -p "${RELEASE_CRATE}"
    ;;

  final)
    check_release_state
    ;;

  *)
    fail "usage: $0 reproduce|final"
    ;;
esac

[ -f "${package_path}" ] ||
  fail "missing ${package_path}"

expect_eq "package SHA-256" \
  "$(sha256 "${package_path}")" \
  "${EXPECTED_PACKAGE_SHA256}"

require_clean_tree
