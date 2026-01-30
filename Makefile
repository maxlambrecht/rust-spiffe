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

-include make/fuzz.mk

MSRV ?= 1.85.0

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
  fmt fmt-check \
  lint build test check all \
  doc-test \
  ci \
  integration-tests \
  coverage \
  msrv \
  examples \
  audit deny \
  lanes \
  spiffe spire-api spiffe-rustls spiffe-rustls-tokio \
  spiffe-all-lanes rustls-all-lanes rustls-tokio-all-lanes

help:
	@echo "Common targets:"
	@echo "  make fmt            Format code"
	@echo "  make fmt-check      Check formatting"
	@echo "  make lint           Clippy (-D warnings)"
	@echo "  make build          Build"
	@echo "  make test           Test (meaningful dev lanes)"
	@echo "  make check          fmt-check + lint + build"
	@echo "  make all            check + test + doc-test + examples"
	@echo "  make clean          cargo clean"
	@echo ""
	@echo "Docs / examples:"
	@echo "  make doc-test       Run doctests explicitly"
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
	@echo "Other:"
	@echo "  make integration-tests   Run ignored tests requiring SPIRE"
	@echo "  make coverage            Generate combined LCOV at ./lcov.info"
	@echo "  make msrv                MSRV policy checks (representative lanes)"
	@echo "  make audit | deny        Dependency checks"
	@echo "  make fuzz                Fuzz targets (see make/fuzz.mk)"
	@echo "  make lanes               Print lane definitions"

clean:
	$(CARGO) clean

fmt:
	$(CARGO) fmt

fmt-check:
	$(CARGO) fmt --check

# -----------------------------------------------------------------------------
# Feature lanes (comma-separated feature sets; no spaces)
# -----------------------------------------------------------------------------
# spiffe: dev lanes should be meaningful (spiffe has no default features).
SPIFFE_DEV_FEATURES := \
  x509-source,jwt-source,jwt,jwt-verify-rust-crypto,tracing

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
  workload-api-full \
  x509-source \
  jwt-source \
  jwt \
  jwt-verify-rust-crypto \
  jwt-verify-aws-lc-rs \
  logging \
  tracing \
  workload-api-full,logging \
  workload-api-full,tracing \
  workload-api-full,tracing,jwt-verify-rust-crypto \
  workload-api-full,tracing,jwt-verify-aws-lc-rs \
  x509-source,logging \
  x509-source,tracing \
  jwt-source,logging \
  jwt-source,tracing

RUSTLS_ALL_FEATURES := \
  $(DEFAULT_LANE) \
  aws-lc-rs \
  ring,tracing \
  ring,logging,parking-lot

SPIRE_API_ALL_FEATURES := \
  $(DEFAULT_LANE)

RUSTLS_TOKIO_ALL_FEATURES := \
  $(DEFAULT_LANE)

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
	    clippy) $(CARGO) clippy --manifest-path $$manifest --all-targets $$extra -- -D warnings ;; \
	    build)  $(CARGO) build  --manifest-path $$manifest $$extra ;; \
	    test)   $(CARGO) test   --manifest-path $$manifest --all-targets $$extra ;; \
	    doc)    $(CARGO) test   --manifest-path $$manifest --doc $$extra ;; \
	    *) echo "unknown cmd: $$cmd" >&2; exit 2 ;; \
	  esac; \
	done
endef

# MSRV helpers (keep policy lanes consistent and readable).
define _msrv_test
	cargo +$(MSRV) test --manifest-path $(1) --all-targets $(2)
endef

define _msrv_doc
	cargo +$(MSRV) test --manifest-path $(1) --doc $(2)
endef

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
# Integration tests (SPIRE)
# -----------------------------------------------------------------------------
integration-tests:
	$(info ==> Run integration tests (ignored))
	@set -euo pipefail; \
	status=0; \
	$(CARGO) test --manifest-path $(SPIFFE_MANIFEST) --features x509-source,jwt-source,jwt -- --ignored || status=1; \
	$(CARGO) test --manifest-path $(SPIFFE_RUSTLS_MANIFEST) -- --ignored || status=1; \
	$(CARGO) test --manifest-path $(SPIFFE_RUSTLS_TOKIO_MANIFEST) -- --ignored || status=1; \
	$(CARGO) test --manifest-path $(SPIRE_API_MANIFEST) -- --ignored || status=1; \
	exit $$status

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
	  $(CARGO) llvm-cov --no-report --manifest-path $(SPIFFE_MANIFEST) test --all-targets $$extra; \
	done

	# spiffe integration lane (ignored)
	$(CARGO) llvm-cov --no-report --manifest-path $(SPIFFE_MANIFEST) test \
	  --features x509-source,jwt-source,jwt -- --ignored

	@set -euo pipefail; \
	for feat in $(RUSTLS_ALL_FEATURES); do \
	  extra=""; \
	  if [ "$$feat" = "$(DEFAULT_LANE)" ]; then \
	    echo "---- spiffe-rustls lane: default"; \
	  else \
	    echo "---- spiffe-rustls lane: --no-default-features --features $$feat"; \
	    extra="--no-default-features --features $$feat"; \
	  fi; \
	  $(CARGO) llvm-cov --no-report --manifest-path $(SPIFFE_RUSTLS_MANIFEST) test --all-targets $$extra; \
	done

	# rustls integration (ignored)
	$(CARGO) llvm-cov --no-report --manifest-path $(SPIFFE_RUSTLS_MANIFEST) test --all-targets -- --ignored

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
	  $(CARGO) llvm-cov --no-report --manifest-path $(SPIFFE_RUSTLS_TOKIO_MANIFEST) test --all-targets $$extra; \
	done

	# spire-api
	$(CARGO) llvm-cov --no-report --manifest-path $(SPIRE_API_MANIFEST) test --all-targets
	$(CARGO) llvm-cov --no-report --manifest-path $(SPIRE_API_MANIFEST) test --all-targets -- --ignored

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
	$(call _msrv_test,$(SPIFFE_MANIFEST),--no-default-features --features x509-source,jwt-source,jwt,jwt-verify-rust-crypto)
	$(call _msrv_doc,$(SPIFFE_MANIFEST),--no-default-features --features x509-source,jwt-source,jwt,jwt-verify-rust-crypto)

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
	$(CARGO) build --manifest-path $(SPIFFE_RUSTLS_MANIFEST) --examples

# -----------------------------------------------------------------------------
# Dependency checks
# -----------------------------------------------------------------------------
audit:
	$(info ==> Dependency audit (cargo-audit))
	@command -v cargo-audit >/dev/null 2>&1 || { echo "Error: cargo-audit not found. Install with: cargo install cargo-audit"; exit 1; }
	$(CARGO) generate-lockfile
	$(CARGO) audit

deny:
	$(info ==> Dependency policy check (cargo-deny))
	@command -v cargo-deny >/dev/null 2>&1 || { echo "Error: cargo-deny not found. Install with: cargo install cargo-deny"; exit 1; }
	$(CARGO) generate-lockfile
	$(CARGO) deny check

# -----------------------------------------------------------------------------
# Lane introspection
# -----------------------------------------------------------------------------
lanes:
	@echo "SPIFFE_DEV_FEATURES:"
	@printf "  %s\n" $(SPIFFE_DEV_FEATURES)
	@echo ""
	@echo "SPIFFE_ALL_FEATURES:"
	@printf "  %s\n" $(SPIFFE_ALL_FEATURES)
	@echo ""

	@echo "RUSTLS_DEV_FEATURES:"
	@printf "  %s\n" $(RUSTLS_DEV_FEATURES)
	@echo ""
	@echo "RUSTLS_ALL_FEATURES:"
	@printf "  %s\n" $(RUSTLS_ALL_FEATURES)
	@echo ""

	@echo "RUSTLS_TOKIO_DEV_FEATURES:"
	@printf "  %s\n" $(RUSTLS_TOKIO_DEV_FEATURES)
	@echo ""
	@echo "RUSTLS_TOKIO_ALL_FEATURES:"
	@printf "  %s\n" $(RUSTLS_TOKIO_ALL_FEATURES)
	@echo ""

	@echo "SPIRE_API_DEV_FEATURES:"
	@printf "  %s\n" $(SPIRE_API_DEV_FEATURES)
	@echo ""
	@echo "SPIRE_API_ALL_FEATURES:"
	@printf "  %s\n" $(SPIRE_API_ALL_FEATURES)
