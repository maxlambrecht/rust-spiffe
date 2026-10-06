# -----------------------------------------------------------------------------
# Workspace Makefile
# -----------------------------------------------------------------------------
#
# This repository contains multiple Rust crates with feature-gated surfaces.
# This Makefile is designed to be:
# - developer-friendly (simple, predictable targets)
# - CI-oriented (explicit feature lanes, integration, MSRV, coverage)
#
# Quick map:
# - Development:   fmt-check | lint | build | test | check | all
# - CI:            per-crate full lane sweeps, integration, msrv, audit, deny
# - SPIRE tests:   integration-tests (ignored tests requiring SPIRE)
# - Docs:          doc-test          (catch example drift early)
# - Examples:      examples          (compile example binaries)
# - Coverage:      coverage          (llvm-cov → lcov.info)
#
# Notes:
# - `spiffe` has no default features; dev/test targets exercise meaningful
#   feature sets instead of relying on defaults.
# - Feature lanes are expressed as comma-separated feature lists (no spaces),
#   allowing safe iteration in shell loops.
# -----------------------------------------------------------------------------

CARGO ?= cargo
SHELL := /bin/bash
LOCKED := --locked

-include make/fuzz.mk

MSRV ?= 1.88.0

SPIFFE_MANIFEST        := spiffe/Cargo.toml
SPIFFE_RUSTLS_MANIFEST := spiffe-rustls/Cargo.toml
SPIFFE_RUSTLS_TOKIO_MANIFEST := spiffe-rustls-tokio/Cargo.toml
SPIRE_API_MANIFEST     := spire-api/Cargo.toml

# -----------------------------------------------------------------------------
# Feature lane sentinel
# -----------------------------------------------------------------------------
# Use a sentinel to represent "default features" lanes in shell loops.
DEFAULT_LANE := @default

# -----------------------------------------------------------------------------
# Target catalog
# -----------------------------------------------------------------------------
.PHONY: \
  help clean \
  fmt fmt-check lock-check \
  lint build test check all \
  doc-test doc-check \
  ci \
  integration-tests \
  coverage \
  msrv \
  examples \
  audit deny release-check \
  lanes \
  spiffe spire-api spiffe-rustls spiffe-rustls-tokio \
  spiffe-all-lanes rustls-all-lanes rustls-tokio-all-lanes \
  spiffe-ci-test spire-api-ci-test spiffe-rustls-ci-test spiffe-rustls-tokio-ci-test

help:
	@echo "Common targets:"
	@echo "  make fmt            Format code"
	@echo "  make fmt-check      Check formatting"
	@echo "  make lock-check     Verify the committed dependency graph"
	@echo "  make lint           Clippy (-D warnings)"
	@echo "  make build          Build"
	@echo "  make test           Test (meaningful dev lanes)"
	@echo "  make check          fmt-check + lint + build"
	@echo "  make all            check + test + doc-test + examples"
	@echo "  make clean          cargo clean"
	@echo ""
	@echo "Docs / examples:"
	@echo "  make doc-test       Run doctests explicitly"
	@echo "  make doc-check      Build published-crate docs with warnings denied"
	@echo "  make examples       Build examples"
	@echo ""
	@echo "CI targets:"
	@echo "  make ci             Full validation suite (all lanes + integration + msrv + audit)"
	@echo ""
	@echo "Per-crate (full lane sweeps):"
	@echo "  make spiffe"
	@echo "  make spiffe-rustls"
	@echo "  make spiffe-rustls-tokio"
	@echo "  make spire-api"
	@echo ""
	@echo "CI test targets (reduced lanes, no clippy/build):"
	@echo "  make spiffe-ci-test"
	@echo "  make spiffe-rustls-ci-test"
	@echo "  make spiffe-rustls-tokio-ci-test"
	@echo "  make spire-api-ci-test"
	@echo ""
	@echo "Other:"
	@echo "  make integration-tests   Run ignored tests requiring SPIRE"
	@echo "  make coverage            Generate combined LCOV at ./lcov.info"
	@echo "  make msrv                MSRV policy checks (representative lanes)"
	@echo "  make audit | deny        Dependency checks"
	@echo "  make release-check CRATE=<name>"
	@echo "  make fuzz                Fuzz targets (see make/fuzz.mk)"
	@echo "  make lanes               Print lane definitions"

clean:
	$(CARGO) clean

fmt:
	$(CARGO) fmt

fmt-check:
	$(CARGO) fmt --check

lock-check:
	@test -f Cargo.lock || { echo "Error: committed workspace Cargo.lock is missing" >&2; exit 1; }
	@git ls-files --error-unmatch -- Cargo.lock >/dev/null 2>&1 || { echo "Error: workspace Cargo.lock is not tracked by git" >&2; exit 1; }
	$(CARGO) metadata $(LOCKED) --no-deps --format-version 1 >/dev/null

# -----------------------------------------------------------------------------
# Feature lanes (comma-separated feature sets; no spaces)
# -----------------------------------------------------------------------------
# spiffe: dev lanes should be meaningful (spiffe has no default features).
SPIFFE_DEV_FEATURES := \
  x509-source,jwt-source,jwt,jwt-verify-rust-crypto,tracing,broker-api

RUSTLS_DEV_FEATURES := \
  $(DEFAULT_LANE) \
  aws-lc-rs

SPIRE_API_DEV_FEATURES := \
  $(DEFAULT_LANE)

RUSTLS_TOKIO_DEV_FEATURES := \
  $(DEFAULT_LANE)

# Full matrix lanes (main CI + coverage).
SPIFFE_ALL_FEATURES := \
  x509 \
  transport \
  transport-grpc \
  workload-api-core \
  workload-api-x509 \
  workload-api-jwt \
  workload-api \
  x509-source \
  jwt-source \
  jwt \
  jwt-verify-rust-crypto \
  jwt-verify-aws-lc-rs \
  logging \
  tracing \
  workload-api,logging \
  workload-api,tracing \
  workload-api,tracing,jwt-verify-rust-crypto \
  workload-api,tracing,jwt-verify-aws-lc-rs \
  x509-source,logging \
  x509-source,tracing \
  jwt-source,logging \
  jwt-source,tracing \
  broker-api

RUSTLS_ALL_FEATURES := \
  $(DEFAULT_LANE) \
  aws-lc-rs \
  ring,tracing \
  ring,logging,parking-lot

SPIRE_API_ALL_FEATURES := \
  $(DEFAULT_LANE)

RUSTLS_TOKIO_ALL_FEATURES := \
  $(DEFAULT_LANE)

# CI feature lanes (representative subset — covers every feature boundary
# without redundant subsets already implied by the feature DAG).
# Clippy runs in the lint job; these lanes are test + doctests only.
SPIFFE_CI_FEATURES := \
  x509 \
  broker-api \
  jwt \
  jwt-verify-rust-crypto \
  jwt-verify-aws-lc-rs \
  x509-source,jwt-source,jwt-verify-rust-crypto,tracing \
  x509-source,jwt-source,jwt-verify-aws-lc-rs,logging

RUSTLS_CI_FEATURES      := $(RUSTLS_ALL_FEATURES)
SPIRE_API_CI_FEATURES   := $(SPIRE_API_ALL_FEATURES)
RUSTLS_TOKIO_CI_FEATURES := $(RUSTLS_TOKIO_ALL_FEATURES)

# SPIRE-backed Workload API integration lane for the spiffe crate.
SPIFFE_WORKLOAD_API_INTEGRATION_FEATURES := x509-source,jwt-source,jwt,workload-api

# Release lanes. The primary lane is the supported, docs.rs-published feature
# set: it is tested in-tree and in the extracted package. Every CI lane is also
# compile-checked from the extracted package, so a feature-gated file missing
# from the archive fails before publishing. The JWT verification backends are
# mutually exclusive, so no lane enables both.
RELEASE_CRATES := spiffe spire-api spiffe-rustls spiffe-rustls-tokio

RELEASE_FEATURES_spiffe              := x509-source,jwt-source,jwt-verify-rust-crypto,broker-api
RELEASE_FEATURES_spire-api           := $(DEFAULT_LANE)
RELEASE_FEATURES_spiffe-rustls       := $(DEFAULT_LANE)
RELEASE_FEATURES_spiffe-rustls-tokio := $(DEFAULT_LANE)

RELEASE_CHECK_LANES_spiffe              := $(SPIFFE_CI_FEATURES)
RELEASE_CHECK_LANES_spire-api           := $(SPIRE_API_CI_FEATURES)
RELEASE_CHECK_LANES_spiffe-rustls       := $(RUSTLS_CI_FEATURES)
RELEASE_CHECK_LANES_spiffe-rustls-tokio := $(RUSTLS_TOKIO_CI_FEATURES)

# Excluded from the workspace in the root Cargo.toml, so the unpacked package
# builds as a standalone crate with its own packaged Cargo.lock.
RELEASE_VERIFY_DIR := target/release-verify

# -----------------------------------------------------------------------------
# Runner helpers
# -----------------------------------------------------------------------------
#
# Iterate feature sets and construct cargo flags safely.
#
# $(call _run_feature_lanes,<manifest>,<label>,<cmd>,<features_list>)
define _run_feature_lanes
	@set -euo pipefail; \
	manifest="$(1)"; \
	label="$(2)"; \
	cmd="$(3)"; \
	features_list='$(4)'; \
	echo "==> $$label"; \
	for feat in $$features_list; do \
	  extra=""; \
	  if [ "$$feat" = "$(DEFAULT_LANE)" ]; then \
	    echo "---- lane: default"; \
	  else \
	    echo "---- lane: --no-default-features --features $$feat"; \
	    extra="--no-default-features --features $$feat"; \
	  fi; \
	  case "$$cmd" in \
	    clippy) $(CARGO) clippy --manifest-path $$manifest --all-targets $$extra $(LOCKED) -- -D warnings ;; \
	    check)  $(CARGO) check  --manifest-path $$manifest --all-targets $$extra $(LOCKED) ;; \
	    build)  $(CARGO) build  --manifest-path $$manifest $$extra $(LOCKED) ;; \
	    test)   $(CARGO) test   --manifest-path $$manifest --all-targets $$extra $(LOCKED) ;; \
	    doc)    $(CARGO) test   --manifest-path $$manifest --doc $$extra $(LOCKED) ;; \
	    *) echo "unknown cmd: $$cmd" >&2; exit 2 ;; \
	  esac; \
	done
endef

# MSRV helpers (keep policy lanes consistent and readable).
define _msrv_test
	cargo +$(MSRV) test --manifest-path $(1) --all-targets $(2) $(LOCKED)
endef

define _msrv_doc
	cargo +$(MSRV) test --manifest-path $(1) --doc $(2) $(LOCKED)
endef

define _assert_spiffe_workload_api_test_discovery
	@set -euo pipefail; \
	echo "==> Verify spiffe workload_api_client test discovery"; \
	list_output="$$( \
	  $(CARGO) test --manifest-path $(SPIFFE_MANIFEST) --no-default-features $(LOCKED) \
	    --features $(SPIFFE_WORKLOAD_API_INTEGRATION_FEATURES) \
	    --test workload_api_client -- --list \
	)"; \
	printf '%s\n' "$$list_output"; \
	test_count="$$(printf '%s\n' "$$list_output" | awk '/: test$$/{count++} END{print count+0}')"; \
	if [ "$$test_count" -eq 0 ]; then \
	  echo "Error: expected workload_api_client integration tests for features $(SPIFFE_WORKLOAD_API_INTEGRATION_FEATURES)" >&2; \
	  exit 1; \
	fi
endef

define _assert_spiffe_workload_api_available
	@set -euo pipefail; \
	echo "==> Verify SPIFFE Workload API availability"; \
	if ! $(CARGO) test --manifest-path $(SPIFFE_MANIFEST) --no-default-features $(LOCKED) \
	  --features $(SPIFFE_WORKLOAD_API_INTEGRATION_FEATURES) \
	  --test workload_api_client \
	  integration_tests_workload_api_client::fetch_x509_svid -- --ignored --exact; then \
	  echo "Error: SPIFFE Workload API preflight failed; verify SPIFFE_ENDPOINT_SOCKET and SPIRE workload registration" >&2; \
	  exit 1; \
	fi
endef

lint build test doc-test doc-check examples integration-tests coverage msrv audit deny: lock-check

check: fmt-check lint build

all: check test doc-test examples

lint: fmt-check
	$(call _run_feature_lanes,$(SPIFFE_MANIFEST),spiffe: clippy (dev lanes),clippy,$(SPIFFE_DEV_FEATURES))
	$(call _run_feature_lanes,$(SPIRE_API_MANIFEST),spire-api: clippy (dev lanes),clippy,$(SPIRE_API_DEV_FEATURES))
	$(call _run_feature_lanes,$(SPIFFE_RUSTLS_MANIFEST),spiffe-rustls: clippy (dev lanes),clippy,$(RUSTLS_DEV_FEATURES))
	$(call _run_feature_lanes,$(SPIFFE_RUSTLS_TOKIO_MANIFEST),spiffe-rustls-tokio: clippy (dev lanes),clippy,$(RUSTLS_TOKIO_DEV_FEATURES))

build:
	$(call _run_feature_lanes,$(SPIFFE_MANIFEST),spiffe: build (dev lanes),build,$(SPIFFE_DEV_FEATURES))
	$(call _run_feature_lanes,$(SPIRE_API_MANIFEST),spire-api: build (dev lanes),build,$(SPIRE_API_DEV_FEATURES))
	$(call _run_feature_lanes,$(SPIFFE_RUSTLS_MANIFEST),spiffe-rustls: build (dev lanes),build,$(RUSTLS_DEV_FEATURES))
	$(call _run_feature_lanes,$(SPIFFE_RUSTLS_TOKIO_MANIFEST),spiffe-rustls-tokio: build (dev lanes),build,$(RUSTLS_TOKIO_DEV_FEATURES))

test:
	$(call _run_feature_lanes,$(SPIFFE_MANIFEST),spiffe: test (dev lanes),test,$(SPIFFE_DEV_FEATURES))
	$(call _run_feature_lanes,$(SPIRE_API_MANIFEST),spire-api: test (dev lanes),test,$(SPIRE_API_DEV_FEATURES))
	$(call _run_feature_lanes,$(SPIFFE_RUSTLS_MANIFEST),spiffe-rustls: test (dev lanes),test,$(RUSTLS_DEV_FEATURES))
	$(call _run_feature_lanes,$(SPIFFE_RUSTLS_TOKIO_MANIFEST),spiffe-rustls-tokio: test (dev lanes),test,$(RUSTLS_TOKIO_DEV_FEATURES))

doc-test:
	$(call _run_feature_lanes,$(SPIFFE_MANIFEST),spiffe: doctests (dev lane),doc,$(SPIFFE_DEV_FEATURES))
	$(call _run_feature_lanes,$(SPIRE_API_MANIFEST),spire-api: doctests,doc,$(SPIRE_API_DEV_FEATURES))
	$(call _run_feature_lanes,$(SPIFFE_RUSTLS_MANIFEST),spiffe-rustls: doctests,doc,$(RUSTLS_DEV_FEATURES))
	$(call _run_feature_lanes,$(SPIFFE_RUSTLS_TOKIO_MANIFEST),spiffe-rustls-tokio: doctests,doc,$(RUSTLS_TOKIO_DEV_FEATURES))

doc-check:
	$(info ==> Published-crate documentation (-D warnings))
	RUSTDOCFLAGS="-D warnings" $(CARGO) doc $(LOCKED) --manifest-path $(SPIFFE_MANIFEST) --no-deps --no-default-features --features $(RELEASE_FEATURES_spiffe)
	RUSTDOCFLAGS="-D warnings" $(CARGO) doc $(LOCKED) --manifest-path $(SPIRE_API_MANIFEST) --no-deps
	RUSTDOCFLAGS="-D warnings" $(CARGO) doc $(LOCKED) --manifest-path $(SPIFFE_RUSTLS_MANIFEST) --no-deps
	RUSTDOCFLAGS="-D warnings" $(CARGO) doc $(LOCKED) --manifest-path $(SPIFFE_RUSTLS_TOKIO_MANIFEST) --no-deps

# -----------------------------------------------------------------------------
# Local validation targets
# -----------------------------------------------------------------------------
ci: fmt-check lint spiffe spire-api spiffe-rustls spiffe-rustls-tokio integration-tests msrv audit deny

# -----------------------------------------------------------------------------
# Per-crate targets (full lane sweeps)
# -----------------------------------------------------------------------------
spiffe: spiffe-all-lanes
spiffe-all-lanes:
	$(call _run_feature_lanes,$(SPIFFE_MANIFEST),spiffe: clippy (all lanes),clippy,$(SPIFFE_ALL_FEATURES))
	$(call _run_feature_lanes,$(SPIFFE_MANIFEST),spiffe: build  (all lanes),build,$(SPIFFE_ALL_FEATURES))
	$(call _run_feature_lanes,$(SPIFFE_MANIFEST),spiffe: test   (all lanes),test,$(SPIFFE_ALL_FEATURES))
	$(call _run_feature_lanes,$(SPIFFE_MANIFEST),spiffe: doctests (all lanes),doc,$(SPIFFE_ALL_FEATURES))

spire-api:
	$(call _run_feature_lanes,$(SPIRE_API_MANIFEST),spire-api: clippy,clippy,$(SPIRE_API_ALL_FEATURES))
	$(call _run_feature_lanes,$(SPIRE_API_MANIFEST),spire-api: build,build,$(SPIRE_API_ALL_FEATURES))
	$(call _run_feature_lanes,$(SPIRE_API_MANIFEST),spire-api: test,test,$(SPIRE_API_ALL_FEATURES))
	$(call _run_feature_lanes,$(SPIRE_API_MANIFEST),spire-api: doctests,doc,$(SPIRE_API_ALL_FEATURES))

spiffe-rustls: rustls-all-lanes
rustls-all-lanes:
	$(call _run_feature_lanes,$(SPIFFE_RUSTLS_MANIFEST),spiffe-rustls: clippy (all lanes),clippy,$(RUSTLS_ALL_FEATURES))
	$(call _run_feature_lanes,$(SPIFFE_RUSTLS_MANIFEST),spiffe-rustls: build  (all lanes),build,$(RUSTLS_ALL_FEATURES))
	$(call _run_feature_lanes,$(SPIFFE_RUSTLS_MANIFEST),spiffe-rustls: test   (all lanes),test,$(RUSTLS_ALL_FEATURES))
	$(call _run_feature_lanes,$(SPIFFE_RUSTLS_MANIFEST),spiffe-rustls: doctests (all lanes),doc,$(RUSTLS_ALL_FEATURES))

spiffe-rustls-tokio: rustls-tokio-all-lanes
rustls-tokio-all-lanes:
	$(call _run_feature_lanes,$(SPIFFE_RUSTLS_TOKIO_MANIFEST),spiffe-rustls-tokio: clippy (all lanes),clippy,$(RUSTLS_TOKIO_ALL_FEATURES))
	$(call _run_feature_lanes,$(SPIFFE_RUSTLS_TOKIO_MANIFEST),spiffe-rustls-tokio: build  (all lanes),build,$(RUSTLS_TOKIO_ALL_FEATURES))
	$(call _run_feature_lanes,$(SPIFFE_RUSTLS_TOKIO_MANIFEST),spiffe-rustls-tokio: test   (all lanes),test,$(RUSTLS_TOKIO_ALL_FEATURES))
	$(call _run_feature_lanes,$(SPIFFE_RUSTLS_TOKIO_MANIFEST),spiffe-rustls-tokio: doctests (all lanes),doc,$(RUSTLS_TOKIO_ALL_FEATURES))

# -----------------------------------------------------------------------------
# Per-crate CI targets (test + doctests only; clippy runs in the lint job)
# -----------------------------------------------------------------------------
# These use reduced, representative feature lanes and skip clippy/build
spiffe-ci-test:
	$(call _run_feature_lanes,$(SPIFFE_MANIFEST),spiffe: test (CI lanes),test,$(SPIFFE_CI_FEATURES))
	$(call _run_feature_lanes,$(SPIFFE_MANIFEST),spiffe: doctests (CI lanes),doc,$(SPIFFE_CI_FEATURES))

spire-api-ci-test:
	$(call _run_feature_lanes,$(SPIRE_API_MANIFEST),spire-api: test,test,$(SPIRE_API_CI_FEATURES))
	$(call _run_feature_lanes,$(SPIRE_API_MANIFEST),spire-api: doctests,doc,$(SPIRE_API_CI_FEATURES))

spiffe-rustls-ci-test:
	$(call _run_feature_lanes,$(SPIFFE_RUSTLS_MANIFEST),spiffe-rustls: test (CI lanes),test,$(RUSTLS_CI_FEATURES))
	$(call _run_feature_lanes,$(SPIFFE_RUSTLS_MANIFEST),spiffe-rustls: doctests (CI lanes),doc,$(RUSTLS_CI_FEATURES))

spiffe-rustls-tokio-ci-test:
	$(call _run_feature_lanes,$(SPIFFE_RUSTLS_TOKIO_MANIFEST),spiffe-rustls-tokio: test,test,$(RUSTLS_TOKIO_CI_FEATURES))
	$(call _run_feature_lanes,$(SPIFFE_RUSTLS_TOKIO_MANIFEST),spiffe-rustls-tokio: doctests,doc,$(RUSTLS_TOKIO_CI_FEATURES))

# -----------------------------------------------------------------------------
# Integration tests (SPIRE)
# -----------------------------------------------------------------------------
integration-tests:
	$(info ==> Run integration tests (ignored))
	$(call _assert_spiffe_workload_api_test_discovery)
	$(call _assert_spiffe_workload_api_available)
	@set -euo pipefail; \
	$(CARGO) test $(LOCKED) --manifest-path $(SPIFFE_MANIFEST) --no-default-features --features $(SPIFFE_WORKLOAD_API_INTEGRATION_FEATURES) -- --ignored; \
	$(CARGO) test $(LOCKED) --manifest-path $(SPIFFE_RUSTLS_MANIFEST) -- --ignored; \
	$(CARGO) test $(LOCKED) --manifest-path $(SPIFFE_RUSTLS_TOKIO_MANIFEST) -- --ignored; \
	$(CARGO) test $(LOCKED) --manifest-path $(SPIRE_API_MANIFEST) -- --ignored

# -----------------------------------------------------------------------------
# Coverage (cargo llvm-cov)
# -----------------------------------------------------------------------------
# Coverage focuses on unit + integration paths and emits a combined LCOV file.
coverage:
	$(info ==> Coverage: unit + integration across feature lanes -> lcov.info)
	$(CARGO) llvm-cov clean --workspace

	@set -euo pipefail; \
	for feat in $(SPIFFE_ALL_FEATURES); do \
	  extra=""; \
	  if [ "$$feat" = "$(DEFAULT_LANE)" ]; then \
	    echo "---- spiffe lane: default"; \
	  else \
	    echo "---- spiffe lane: --no-default-features --features $$feat"; \
	    extra="--no-default-features --features $$feat"; \
	  fi; \
	  $(CARGO) llvm-cov $(LOCKED) --no-report --manifest-path $(SPIFFE_MANIFEST) test --all-targets $$extra; \
	done

	# spiffe integration lane (ignored)
	$(call _assert_spiffe_workload_api_test_discovery)
	$(CARGO) llvm-cov $(LOCKED) --no-report --manifest-path $(SPIFFE_MANIFEST) test \
	  --no-default-features --features $(SPIFFE_WORKLOAD_API_INTEGRATION_FEATURES) -- --ignored

	@set -euo pipefail; \
	for feat in $(RUSTLS_ALL_FEATURES); do \
	  extra=""; \
	  if [ "$$feat" = "$(DEFAULT_LANE)" ]; then \
	    echo "---- spiffe-rustls lane: default"; \
	  else \
	    echo "---- spiffe-rustls lane: --no-default-features --features $$feat"; \
	    extra="--no-default-features --features $$feat"; \
	  fi; \
	  $(CARGO) llvm-cov $(LOCKED) --no-report --manifest-path $(SPIFFE_RUSTLS_MANIFEST) test --all-targets $$extra; \
	done

	# rustls integration (ignored)
	$(CARGO) llvm-cov $(LOCKED) --no-report --manifest-path $(SPIFFE_RUSTLS_MANIFEST) test --all-targets -- --ignored

	# rustls-tokio
	@set -euo pipefail; \
	for feat in $(RUSTLS_TOKIO_ALL_FEATURES); do \
	  extra=""; \
	  if [ "$$feat" = "$(DEFAULT_LANE)" ]; then \
	    echo "---- spiffe-rustls-tokio lane: default"; \
	  else \
	    echo "---- spiffe-rustls-tokio lane: --no-default-features --features $$feat"; \
	    extra="--no-default-features --features $$feat"; \
	  fi; \
	  $(CARGO) llvm-cov $(LOCKED) --no-report --manifest-path $(SPIFFE_RUSTLS_TOKIO_MANIFEST) test --all-targets $$extra; \
	done

	# spire-api
	$(CARGO) llvm-cov $(LOCKED) --no-report --manifest-path $(SPIRE_API_MANIFEST) test --all-targets
	$(CARGO) llvm-cov $(LOCKED) --no-report --manifest-path $(SPIRE_API_MANIFEST) test --all-targets -- --ignored

	$(CARGO) llvm-cov report \
	  --lcov \
	  --output-path lcov.info \
	  --ignore-filename-regex 'proto/|pb/|spire-api-sdk/|build\.rs|spiffe-rustls-grpc-examples/src/|xtask/src/'

# -----------------------------------------------------------------------------
# MSRV policy checks
# -----------------------------------------------------------------------------
msrv:
	$(info ==> MSRV policy check: Rust $(MSRV))
	cargo +$(MSRV) --version

	$(info ==> spiffe (MSRV))
	$(call _msrv_test,$(SPIFFE_MANIFEST),--no-default-features --features x509)
	$(call _msrv_test,$(SPIFFE_MANIFEST),--no-default-features --features transport-grpc)
	$(call _msrv_test,$(SPIFFE_MANIFEST),--no-default-features --features x509-source,jwt-source,jwt,jwt-verify-rust-crypto,broker-api)
	$(call _msrv_doc,$(SPIFFE_MANIFEST),--no-default-features --features x509-source,jwt-source,jwt,jwt-verify-rust-crypto,broker-api)

	$(info ==> spire-api (MSRV))
	$(call _msrv_test,$(SPIRE_API_MANIFEST),)
	$(call _msrv_doc,$(SPIRE_API_MANIFEST),)

	$(info ==> spiffe-rustls (MSRV))
	$(call _msrv_test,$(SPIFFE_RUSTLS_MANIFEST),)
	$(call _msrv_test,$(SPIFFE_RUSTLS_MANIFEST),--no-default-features --features aws-lc-rs)
	$(call _msrv_doc,$(SPIFFE_RUSTLS_MANIFEST),)

	$(info ==> spiffe-rustls-tokio (MSRV))
	$(call _msrv_test,$(SPIFFE_RUSTLS_TOKIO_MANIFEST),)
	$(call _msrv_doc,$(SPIFFE_RUSTLS_TOKIO_MANIFEST),)

# -----------------------------------------------------------------------------
# Examples
# -----------------------------------------------------------------------------
examples:
	$(info ==> Build examples)
	$(CARGO) build $(LOCKED) --manifest-path $(SPIFFE_RUSTLS_MANIFEST) --examples

# -----------------------------------------------------------------------------
# Dependency checks
# -----------------------------------------------------------------------------
audit:
	$(info ==> Dependency audit (cargo-audit))
	@command -v cargo-audit >/dev/null 2>&1 || { echo "Error: cargo-audit not found. Install with: cargo install cargo-audit"; exit 1; }
	$(CARGO) audit --file Cargo.lock

deny:
	$(info ==> Dependency policy check (cargo-deny))
	@command -v cargo-deny >/dev/null 2>&1 || { echo "Error: cargo-deny not found. Install with: cargo install cargo-deny"; exit 1; }
	$(CARGO) deny check

# Release-only assurance checks. This deliberately stays out of normal PR CI:
# cargo-semver-checks compares against crates.io and can fail for registry or
# toolchain reasons unrelated to a source change. The publish workflow runs this
# in its preflight job, which has no OIDC permission.
#
# The archive path is derived from the target directory, so pin it instead of
# inheriting CARGO_TARGET_DIR from the environment.
_release_cargo_flags = $(if $(filter $(DEFAULT_LANE),$(1)),,--no-default-features --features $(1))
_release_semver_flags = $(if $(filter $(DEFAULT_LANE),$(1)),--default-features,--only-explicit-features --features $(1))
_require_clean_tree = status="$$(git status --porcelain --untracked-files=all)" && test -z "$$status" || { echo "Error: $(1)" >&2; exit 1; }
# Cargo packages initialized submodule files (spire-api ships spire-api-sdk).
_require_pinned_submodules = subs="$$(git submodule status --recursive)" && ! printf '%s\n' "$$subs" | grep -q '^[-+U]' || { echo "Error: run 'git submodule update --init --recursive'; packaged submodules must match their committed revisions" >&2; exit 1; }

release-check: export CARGO_TARGET_DIR := $(CURDIR)/target
release-check: lock-check
	$(if $(filter-out 1,$(words $(CRATE)))$(filter-out $(RELEASE_CRATES),$(CRATE)),$(error CRATE must be exactly one of: $(RELEASE_CRATES)))
	@command -v cargo-semver-checks >/dev/null 2>&1 || { echo "Error: cargo-semver-checks not found. Install with: cargo install cargo-semver-checks --locked"; exit 1; }
	@$(call _require_clean_tree,release validation requires a clean working tree)
	@$(_require_pinned_submodules)
	@echo "==> Release metadata: $(CRATE)"
	$(CARGO) metadata $(LOCKED) --no-deps --format-version 1 --manifest-path $(CRATE)/Cargo.toml >/dev/null
	$(call _run_feature_lanes,$(CRATE)/Cargo.toml,$(CRATE): release tests,test,$(RELEASE_FEATURES_$(CRATE)))
	@echo "==> Release docs: $(CRATE)"
	RUSTDOCFLAGS="-D warnings" $(CARGO) doc $(LOCKED) --manifest-path $(CRATE)/Cargo.toml --no-deps $(call _release_cargo_flags,$(RELEASE_FEATURES_$(CRATE)))
	@echo "==> SemVer compatibility: $(CRATE)"
	$(CARGO) semver-checks --manifest-path $(CRATE)/Cargo.toml $(call _release_semver_flags,$(RELEASE_FEATURES_$(CRATE)))
	@echo "==> Package (Cargo verifies the default-feature build): $(CRATE)"
	$(CARGO) package $(LOCKED) -p $(CRATE)
	@set -euo pipefail; \
	pkgid="$$($(CARGO) pkgid $(LOCKED) -p $(CRATE))"; \
	version="$${pkgid##*#}"; \
	version="$${version##*@}"; \
	crate_file="$$CARGO_TARGET_DIR/package/$(CRATE)-$$version.crate"; \
	unpack_dir="$(RELEASE_VERIFY_DIR)/$(CRATE)"; \
	echo "==> Unpack and inspect $$crate_file"; \
	entries="$$(tar -tzf "$$crate_file")"; \
	bad="$$(printf '%s\n' "$$entries" | awk -v p="$(CRATE)-$$version/" 'index($$0, p) != 1 || $$0 ~ /(^|\/)\.\.(\/|$$)/')"; \
	if [ -n "$$bad" ]; then echo "Error: unexpected paths in $$crate_file:" >&2; echo "$$bad" >&2; exit 1; fi; \
	rm -rf "$(RELEASE_VERIFY_DIR)"; \
	mkdir -p "$$unpack_dir"; \
	tar -xzf "$$crate_file" -C "$$unpack_dir" --strip-components=1; \
	vcs_info="$$unpack_dir/.cargo_vcs_info.json"; \
	head="$$(git rev-parse HEAD)"; \
	grep -Fq "\"sha1\": \"$$head\"" "$$vcs_info" || { echo "Error: $$vcs_info does not record HEAD $$head" >&2; exit 1; }; \
	grep -Fq "\"path_in_vcs\": \"$(CRATE)\"" "$$vcs_info" || { echo "Error: $$vcs_info does not record path $(CRATE)" >&2; exit 1; }; \
	if grep -Fq '"dirty"' "$$vcs_info"; then echo "Error: $$crate_file was packaged from a dirty tree" >&2; exit 1; fi; \
	test -f "$$unpack_dir/Cargo.lock" || { echo "Error: $$crate_file has no Cargo.lock" >&2; exit 1; }; \
	unpacked="$$($(CARGO) pkgid $(LOCKED) --manifest-path "$$unpack_dir/Cargo.toml")"; \
	test "$${unpacked##*#}" = "$$version" || { echo "Error: unpacked manifest is $$unpacked, expected $(CRATE) $$version" >&2; exit 1; }
	$(call _run_feature_lanes,$(RELEASE_VERIFY_DIR)/$(CRATE)/Cargo.toml,$(CRATE): extracted-package tests,test,$(RELEASE_FEATURES_$(CRATE)))
	$(call _run_feature_lanes,$(RELEASE_VERIFY_DIR)/$(CRATE)/Cargo.toml,$(CRATE): extracted-package doctests,doc,$(RELEASE_FEATURES_$(CRATE)))
	$(call _run_feature_lanes,$(RELEASE_VERIFY_DIR)/$(CRATE)/Cargo.toml,$(CRATE): extracted-package feature lanes,check,$(RELEASE_CHECK_LANES_$(CRATE)))
	@$(call _require_clean_tree,release checks modified the working tree)
	$(MAKE) deny

# -----------------------------------------------------------------------------
# Lane introspection
# -----------------------------------------------------------------------------
lanes:
	@echo "SPIFFE_DEV_FEATURES:"
	@printf "  %s\n" $(SPIFFE_DEV_FEATURES)
	@echo ""
	@echo "SPIFFE_CI_FEATURES:"
	@printf "  %s\n" $(SPIFFE_CI_FEATURES)
	@echo ""
	@echo "SPIFFE_ALL_FEATURES:"
	@printf "  %s\n" $(SPIFFE_ALL_FEATURES)
	@echo ""

	@echo "RUSTLS_DEV_FEATURES:"
	@printf "  %s\n" $(RUSTLS_DEV_FEATURES)
	@echo ""
	@echo "RUSTLS_CI_FEATURES:"
	@printf "  %s\n" $(RUSTLS_CI_FEATURES)
	@echo ""
	@echo "RUSTLS_ALL_FEATURES:"
	@printf "  %s\n" $(RUSTLS_ALL_FEATURES)
	@echo ""

	@echo "RUSTLS_TOKIO_DEV_FEATURES:"
	@printf "  %s\n" $(RUSTLS_TOKIO_DEV_FEATURES)
	@echo ""
	@echo "RUSTLS_TOKIO_CI_FEATURES:"
	@printf "  %s\n" $(RUSTLS_TOKIO_CI_FEATURES)
	@echo ""
	@echo "RUSTLS_TOKIO_ALL_FEATURES:"
	@printf "  %s\n" $(RUSTLS_TOKIO_ALL_FEATURES)
	@echo ""

	@echo "SPIRE_API_DEV_FEATURES:"
	@printf "  %s\n" $(SPIRE_API_DEV_FEATURES)
	@echo ""
	@echo "SPIRE_API_CI_FEATURES:"
	@printf "  %s\n" $(SPIRE_API_CI_FEATURES)
	@echo ""
	@echo "SPIRE_API_ALL_FEATURES:"
	@printf "  %s\n" $(SPIRE_API_ALL_FEATURES)
