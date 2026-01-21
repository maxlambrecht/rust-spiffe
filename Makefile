CARGO ?= cargo
SHELL := /bin/bash

-include make/fuzz.mk

# -----------------------------------------------------------------------------
# Policy
# -----------------------------------------------------------------------------

MSRV ?= 1.85.0

SPIFFE_MANIFEST        := spiffe/Cargo.toml
SPIFFE_RUSTLS_MANIFEST := spiffe-rustls/Cargo.toml
SPIRE_API_MANIFEST     := spire-api/Cargo.toml

.PHONY: \
  all audit \
  check ci clean coverage \
  deny \
  examples \
  fmt fmt-check full \
  help \
  integration-tests \
  lint \
  msrv \
  quicktest \
  spiffe spiffe-rustls spire-api \
  test test-ci

help:
	@echo "Targets:"
	@echo "  make all               Run all crate checks (spiffe, spire-api, spiffe-rustls)"
	@echo "  make full              all + integration-tests"
	@echo "  make ci                Run full CI checks (all + msrv)"
	@echo "  make coverage          Generate combined coverage (feature lanes + integration) -> lcov.info"
	@echo "  make check             Quick check (fmt + clippy + build, no tests)"
	@echo "  make lint              Run clippy on all crates"
	@echo "  make test              Run tests on all crates (default features)"
	@echo "  make msrv              Verify MSRV ($(MSRV)) across key lanes"
	@echo "  make integration-tests Run integration tests"
	@echo "  make spiffe            Clippy/build/test across spiffe feature lanes"
	@echo "  make spire-api         Clippy/build/test"
	@echo "  make spiffe-rustls     Clippy/build/test (default + aws-lc-rs + tracing lane)"
	@echo "  make examples          Build all examples"
	@echo "  make audit             Run cargo-audit (requires cargo-audit)"
	@echo "  make deny              Run cargo-deny (requires cargo-deny)"
	@echo "  make fmt | fmt-check   rustfmt"
	@echo "  make fuzz              Run fuzz tests (see make/fuzz.mk)"
	@echo "  make clean             cargo clean"

# -----------------------------------------------------------------------------
# Helpers
# -----------------------------------------------------------------------------

# $(call cargo_build,<manifest>,<extra args>)
define cargo_build
	$(CARGO) build --manifest-path $(1) $(2)
endef

# $(call cargo_test,<manifest>,<extra args>)
define cargo_test
	$(CARGO) test --manifest-path $(1) --all-targets $(2)
endef

# $(call cargo_clippy,<manifest>,<extra args>)
define cargo_clippy
	$(CARGO) clippy --manifest-path $(1) --all-targets $(2)
endef

# $(call cargo_clippy_deny_warnings,<manifest>,<extra args>)
define cargo_clippy_deny_warnings
	$(CARGO) clippy --manifest-path $(1) --all-targets $(2) -- -D warnings
endef

# MSRV helpers (cargo +<toolchain>)
# $(call msrv_test,<manifest>,<extra args>)
define msrv_test
	cargo +$(MSRV) test --manifest-path $(1) --all-targets $(2)
endef

# -----------------------------------------------------------------------------
# Global targets
# -----------------------------------------------------------------------------

all: fmt-check spiffe spire-api spiffe-rustls
	@true

full: all integration-tests
	@true

fmt:
	$(CARGO) fmt

fmt-check:
	$(CARGO) fmt --check

clean:
	$(CARGO) clean

# -----------------------------------------------------------------------------
# Convenience targets
# -----------------------------------------------------------------------------

check: fmt-check
	$(info ==> Quick check: clippy + build)
	$(call cargo_clippy_deny_warnings,$(SPIFFE_MANIFEST),)
	$(call cargo_clippy_deny_warnings,$(SPIRE_API_MANIFEST),)
	$(call cargo_clippy_deny_warnings,$(SPIFFE_RUSTLS_MANIFEST),)

	$(call cargo_build,$(SPIFFE_MANIFEST),)
	$(call cargo_build,$(SPIRE_API_MANIFEST),)
	$(call cargo_build,$(SPIFFE_RUSTLS_MANIFEST),)

lint: fmt-check
	$(info ==> Lint: clippy on all crates)
	$(call cargo_clippy_deny_warnings,$(SPIFFE_MANIFEST),)
	$(call cargo_clippy_deny_warnings,$(SPIRE_API_MANIFEST),)
	$(call cargo_clippy_deny_warnings,$(SPIFFE_RUSTLS_MANIFEST),)

test:
	$(info ==> Test: run tests on all crates)
	$(call cargo_test,$(SPIFFE_MANIFEST),)
	$(call cargo_test,$(SPIRE_API_MANIFEST),)
	$(call cargo_test,$(SPIFFE_RUSTLS_MANIFEST),)

.PHONY: quicktest test-ci

quicktest:
	$(info ==> Quick tests: primary runtime features)
	$(CARGO) test --manifest-path $(SPIFFE_MANIFEST) \
		--no-default-features --features x509-source,jwt-source,jwt
	$(CARGO) test --manifest-path $(SPIFFE_RUSTLS_MANIFEST)
	$(CARGO) test --manifest-path $(SPIRE_API_MANIFEST)

test-ci: fmt-check lint quicktest
	@true

# -----------------------------------------------------------------------------
# Coverage (cargo llvm-cov)
# -----------------------------------------------------------------------------

coverage:
	$(info ==> Coverage: unit + integration tests across feature lanes)
	$(CARGO) llvm-cov clean --workspace

	# -----------------------
	# spiffe (feature lanes)
	# -----------------------
	$(CARGO) llvm-cov --no-report --manifest-path $(SPIFFE_MANIFEST) test
	$(CARGO) llvm-cov --no-report --manifest-path $(SPIFFE_MANIFEST) test --no-default-features --features x509
	$(CARGO) llvm-cov --no-report --manifest-path $(SPIFFE_MANIFEST) test --no-default-features --features transport
	$(CARGO) llvm-cov --no-report --manifest-path $(SPIFFE_MANIFEST) test --no-default-features --features transport-grpc
	$(CARGO) llvm-cov --no-report --manifest-path $(SPIFFE_MANIFEST) test --no-default-features --features workload-api
	$(CARGO) llvm-cov --no-report --manifest-path $(SPIFFE_MANIFEST) test --no-default-features --features workload-api-full
	$(CARGO) llvm-cov --no-report --manifest-path $(SPIFFE_MANIFEST) test --no-default-features --features x509-source
	$(CARGO) llvm-cov --no-report --manifest-path $(SPIFFE_MANIFEST) test --no-default-features --features jwt-source
	$(CARGO) llvm-cov --no-report --manifest-path $(SPIFFE_MANIFEST) test --no-default-features --features jwt
	$(CARGO) llvm-cov --no-report --manifest-path $(SPIFFE_MANIFEST) test --no-default-features --features jwt-verify-rust-crypto
	$(CARGO) llvm-cov --no-report --manifest-path $(SPIFFE_MANIFEST) test --no-default-features --features jwt-verify-aws-lc-rs
	$(CARGO) llvm-cov --no-report --manifest-path $(SPIFFE_MANIFEST) test --no-default-features --features logging
	$(CARGO) llvm-cov --no-report --manifest-path $(SPIFFE_MANIFEST) test --no-default-features --features tracing

	# Integration tests for spiffe (SPIRE-dependent)
	$(CARGO) llvm-cov --no-report --manifest-path $(SPIFFE_MANIFEST) test \
		--features x509-source,jwt-source,jwt -- --ignored

	# -----------------------
	# spiffe-rustls (lanes)
	# -----------------------
	$(CARGO) llvm-cov --no-report --manifest-path $(SPIFFE_RUSTLS_MANIFEST) test
	$(CARGO) llvm-cov --no-report --manifest-path $(SPIFFE_RUSTLS_MANIFEST) test --no-default-features --features aws-lc-rs
	$(CARGO) llvm-cov --no-report --manifest-path $(SPIFFE_RUSTLS_MANIFEST) test --no-default-features --features ring,tracing
	$(CARGO) llvm-cov --no-report --manifest-path $(SPIFFE_RUSTLS_MANIFEST) test --no-default-features --features ring,logging,parking-lot

	# Integration tests
	$(CARGO) llvm-cov --no-report --manifest-path $(SPIFFE_RUSTLS_MANIFEST) test -- --ignored

	# -----------------------
	# spire-api
	# -----------------------
	$(CARGO) llvm-cov --no-report --manifest-path $(SPIRE_API_MANIFEST) test
	$(CARGO) llvm-cov --no-report --manifest-path $(SPIRE_API_MANIFEST) test -- --ignored

	# -----------------------
	# Emit final combined LCOV
	# -----------------------
	$(CARGO) llvm-cov report \
		--lcov \
		--output-path lcov.info \
		--ignore-filename-regex 'proto/|pb/|spire-api-sdk/|build\.rs|spiffe-rustls-grpc-examples/src/|xtask/src/'

# -----------------------------------------------------------------------------
# MSRV policy check
# -----------------------------------------------------------------------------
# Keep MSRV lanes limited but representative of the major feature surfaces.

msrv:
	$(info ==> MSRV policy check: Rust $(MSRV))
	cargo +$(MSRV) --version

	$(info ==> spiffe (MSRV))
	$(call msrv_test,$(SPIFFE_MANIFEST),)
	$(call msrv_test,$(SPIFFE_MANIFEST),--no-default-features --features x509)
	$(call msrv_test,$(SPIFFE_MANIFEST),--no-default-features --features transport)
	$(call msrv_test,$(SPIFFE_MANIFEST),--no-default-features --features transport-grpc)
	$(call msrv_test,$(SPIFFE_MANIFEST),--no-default-features --features workload-api)
	$(call msrv_test,$(SPIFFE_MANIFEST),--no-default-features --features x509-source)
	$(call msrv_test,$(SPIFFE_MANIFEST),--no-default-features --features jwt-source)
	$(call msrv_test,$(SPIFFE_MANIFEST),--no-default-features --features jwt)
	$(call msrv_test,$(SPIFFE_MANIFEST),--no-default-features --features jwt-verify-rust-crypto)
	$(call msrv_test,$(SPIFFE_MANIFEST),--no-default-features --features jwt-verify-aws-lc-rs)
	$(call msrv_test,$(SPIFFE_MANIFEST),--no-default-features --features logging)
	$(call msrv_test,$(SPIFFE_MANIFEST),--no-default-features --features tracing)

	$(info ==> spire-api (MSRV))
	$(call msrv_test,$(SPIRE_API_MANIFEST),)

	$(info ==> spiffe-rustls (MSRV))
	$(call msrv_test,$(SPIFFE_RUSTLS_MANIFEST),)
	$(call msrv_test,$(SPIFFE_RUSTLS_MANIFEST),--no-default-features --features aws-lc-rs)
	$(call msrv_test,$(SPIFFE_RUSTLS_MANIFEST),--no-default-features --features ring,tracing)
	$(call msrv_test,$(SPIFFE_RUSTLS_MANIFEST),--no-default-features --features ring,logging)
	$(call msrv_test,$(SPIFFE_RUSTLS_MANIFEST),--no-default-features --features ring,parking-lot)

# -----------------------------------------------------------------------------
# Integration tests (SPIRE)
# -----------------------------------------------------------------------------

integration-tests:
	$(info ==> Run integration tests)
	@set -euo pipefail; \
	status=0; \
	$(CARGO) test --manifest-path $(SPIFFE_MANIFEST) --features x509-source,jwt-source,jwt -- --ignored || status=1; \
	$(CARGO) test --manifest-path $(SPIFFE_RUSTLS_MANIFEST) -- --ignored || status=1; \
	$(CARGO) test --manifest-path $(SPIRE_API_MANIFEST) -- --ignored || status=1; \
	exit $$status

# -----------------------------------------------------------------------------
# spiffe
# -----------------------------------------------------------------------------

spiffe:
	$(info ==> spiffe: clippy (feature lanes))
	$(call cargo_clippy_deny_warnings,$(SPIFFE_MANIFEST),)
	$(call cargo_clippy_deny_warnings,$(SPIFFE_MANIFEST),--no-default-features --features x509)
	$(call cargo_clippy_deny_warnings,$(SPIFFE_MANIFEST),--no-default-features --features transport)
	$(call cargo_clippy_deny_warnings,$(SPIFFE_MANIFEST),--no-default-features --features transport-grpc)
	$(call cargo_clippy_deny_warnings,$(SPIFFE_MANIFEST),--no-default-features --features workload-api-core)
	$(call cargo_clippy_deny_warnings,$(SPIFFE_MANIFEST),--no-default-features --features workload-api-x509)
	$(call cargo_clippy_deny_warnings,$(SPIFFE_MANIFEST),--no-default-features --features workload-api-jwt)
	$(call cargo_clippy_deny_warnings,$(SPIFFE_MANIFEST),--no-default-features --features workload-api)
	$(call cargo_clippy_deny_warnings,$(SPIFFE_MANIFEST),--no-default-features --features workload-api-full)
	$(call cargo_clippy_deny_warnings,$(SPIFFE_MANIFEST),--no-default-features --features x509-source)
	$(call cargo_clippy_deny_warnings,$(SPIFFE_MANIFEST),--no-default-features --features jwt-source)
	$(call cargo_clippy_deny_warnings,$(SPIFFE_MANIFEST),--no-default-features --features jwt)
	$(call cargo_clippy_deny_warnings,$(SPIFFE_MANIFEST),--no-default-features --features jwt-verify-rust-crypto)
	$(call cargo_clippy_deny_warnings,$(SPIFFE_MANIFEST),--no-default-features --features jwt-verify-aws-lc-rs)
	$(call cargo_clippy_deny_warnings,$(SPIFFE_MANIFEST),--no-default-features --features logging)
	$(call cargo_clippy_deny_warnings,$(SPIFFE_MANIFEST),--no-default-features --features tracing)

	$(call cargo_clippy_deny_warnings,$(SPIFFE_MANIFEST),--no-default-features --features workload-api-full,logging)
	$(call cargo_clippy_deny_warnings,$(SPIFFE_MANIFEST),--no-default-features --features workload-api-full,tracing)
	$(call cargo_clippy_deny_warnings,$(SPIFFE_MANIFEST),--no-default-features --features workload-api-full,tracing,jwt-verify-rust-crypto)
	$(call cargo_clippy_deny_warnings,$(SPIFFE_MANIFEST),--no-default-features --features workload-api-full,tracing,jwt-verify-aws-lc-rs)
	$(call cargo_clippy_deny_warnings,$(SPIFFE_MANIFEST),--no-default-features --features x509-source,logging)
	$(call cargo_clippy_deny_warnings,$(SPIFFE_MANIFEST),--no-default-features --features x509-source,tracing)
	$(call cargo_clippy_deny_warnings,$(SPIFFE_MANIFEST),--no-default-features --features jwt-source,logging)
	$(call cargo_clippy_deny_warnings,$(SPIFFE_MANIFEST),--no-default-features --features jwt-source,tracing)

	$(info ==> spiffe: build (feature lanes))
	$(call cargo_build,$(SPIFFE_MANIFEST),)
	$(call cargo_build,$(SPIFFE_MANIFEST),--no-default-features --features x509)
	$(call cargo_build,$(SPIFFE_MANIFEST),--no-default-features --features transport)
	$(call cargo_build,$(SPIFFE_MANIFEST),--no-default-features --features transport-grpc)
	$(call cargo_build,$(SPIFFE_MANIFEST),--no-default-features --features workload-api-core)
	$(call cargo_build,$(SPIFFE_MANIFEST),--no-default-features --features workload-api-x509)
	$(call cargo_build,$(SPIFFE_MANIFEST),--no-default-features --features workload-api-jwt)
	$(call cargo_build,$(SPIFFE_MANIFEST),--no-default-features --features workload-api)
	$(call cargo_build,$(SPIFFE_MANIFEST),--no-default-features --features workload-api-full)
	$(call cargo_build,$(SPIFFE_MANIFEST),--no-default-features --features x509-source)
	$(call cargo_build,$(SPIFFE_MANIFEST),--no-default-features --features jwt-source)
	$(call cargo_build,$(SPIFFE_MANIFEST),--no-default-features --features jwt)
	$(call cargo_build,$(SPIFFE_MANIFEST),--no-default-features --features jwt-verify-rust-crypto)
	$(call cargo_build,$(SPIFFE_MANIFEST),--no-default-features --features jwt-verify-aws-lc-rs)
	$(call cargo_build,$(SPIFFE_MANIFEST),--no-default-features --features logging)
	$(call cargo_build,$(SPIFFE_MANIFEST),--no-default-features --features tracing)

	$(call cargo_build,$(SPIFFE_MANIFEST),--no-default-features --features workload-api-full,logging)
	$(call cargo_build,$(SPIFFE_MANIFEST),--no-default-features --features workload-api-full,tracing)
	$(call cargo_build,$(SPIFFE_MANIFEST),--no-default-features --features workload-api-full,tracing,jwt-verify-rust-crypto)
	$(call cargo_build,$(SPIFFE_MANIFEST),--no-default-features --features workload-api-full,tracing,jwt-verify-aws-lc-rs)
	$(call cargo_build,$(SPIFFE_MANIFEST),--no-default-features --features x509-source,logging)
	$(call cargo_build,$(SPIFFE_MANIFEST),--no-default-features --features x509-source,tracing)
	$(call cargo_build,$(SPIFFE_MANIFEST),--no-default-features --features jwt-source,logging)
	$(call cargo_build,$(SPIFFE_MANIFEST),--no-default-features --features jwt-source,tracing)

	$(info ==> spiffe: test (feature lanes))
	$(call cargo_test,$(SPIFFE_MANIFEST),)
	$(call cargo_test,$(SPIFFE_MANIFEST),--no-default-features --features x509)
	$(call cargo_test,$(SPIFFE_MANIFEST),--no-default-features --features transport)
	$(call cargo_test,$(SPIFFE_MANIFEST),--no-default-features --features transport-grpc)
	$(call cargo_test,$(SPIFFE_MANIFEST),--no-default-features --features workload-api-core)
	$(call cargo_test,$(SPIFFE_MANIFEST),--no-default-features --features workload-api-x509)
	$(call cargo_test,$(SPIFFE_MANIFEST),--no-default-features --features workload-api-jwt)
	$(call cargo_test,$(SPIFFE_MANIFEST),--no-default-features --features workload-api-full)
	$(call cargo_test,$(SPIFFE_MANIFEST),--no-default-features --features x509-source)
	$(call cargo_test,$(SPIFFE_MANIFEST),--no-default-features --features jwt-source)
	$(call cargo_test,$(SPIFFE_MANIFEST),--no-default-features --features jwt)
	$(call cargo_test,$(SPIFFE_MANIFEST),--no-default-features --features jwt-verify-rust-crypto)
	$(call cargo_test,$(SPIFFE_MANIFEST),--no-default-features --features jwt-verify-aws-lc-rs)
	$(call cargo_test,$(SPIFFE_MANIFEST),--no-default-features --features logging)
	$(call cargo_test,$(SPIFFE_MANIFEST),--no-default-features --features tracing)

	$(call cargo_test,$(SPIFFE_MANIFEST),--no-default-features --features workload-api-full,logging)
	$(call cargo_test,$(SPIFFE_MANIFEST),--no-default-features --features workload-api-full,tracing)
	$(call cargo_test,$(SPIFFE_MANIFEST),--no-default-features --features workload-api-full,tracing,jwt-verify-rust-crypto)
	$(call cargo_test,$(SPIFFE_MANIFEST),--no-default-features --features workload-api-full,tracing,jwt-verify-aws-lc-rs)
	$(call cargo_test,$(SPIFFE_MANIFEST),--no-default-features --features x509-source,logging)
	$(call cargo_test,$(SPIFFE_MANIFEST),--no-default-features --features x509-source,tracing)
	$(call cargo_test,$(SPIFFE_MANIFEST),--no-default-features --features jwt-source,logging)
	$(call cargo_test,$(SPIFFE_MANIFEST),--no-default-features --features jwt-source,tracing)

# -----------------------------------------------------------------------------
# spire-api
# -----------------------------------------------------------------------------

spire-api:
	$(info ==> spire-api: clippy)
	$(call cargo_clippy_deny_warnings,$(SPIRE_API_MANIFEST),)

	$(info ==> spire-api: build)
	$(call cargo_build,$(SPIRE_API_MANIFEST),)

	$(info ==> spire-api: test)
	$(call cargo_test,$(SPIRE_API_MANIFEST),)

# -----------------------------------------------------------------------------
# spiffe-rustls
# -----------------------------------------------------------------------------

spiffe-rustls:
	$(info ==> spiffe-rustls: clippy)
	$(call cargo_clippy_deny_warnings,$(SPIFFE_RUSTLS_MANIFEST),)
	$(call cargo_clippy_deny_warnings,$(SPIFFE_RUSTLS_MANIFEST),--no-default-features --features aws-lc-rs)
	$(call cargo_clippy_deny_warnings,$(SPIFFE_RUSTLS_MANIFEST),--no-default-features --features ring,tracing)
	$(call cargo_clippy_deny_warnings,$(SPIFFE_RUSTLS_MANIFEST),--no-default-features --features ring,logging,parking-lot)

	$(info ==> spiffe-rustls: build)
	$(call cargo_build,$(SPIFFE_RUSTLS_MANIFEST),)
	$(call cargo_build,$(SPIFFE_RUSTLS_MANIFEST),--no-default-features --features aws-lc-rs)
	$(call cargo_build,$(SPIFFE_RUSTLS_MANIFEST),--no-default-features --features ring,tracing)
	$(call cargo_build,$(SPIFFE_RUSTLS_MANIFEST),--no-default-features --features ring,logging,parking-lot)

	$(info ==> spiffe-rustls: test)
	$(call cargo_test,$(SPIFFE_RUSTLS_MANIFEST),)
	$(call cargo_test,$(SPIFFE_RUSTLS_MANIFEST),--no-default-features --features aws-lc-rs)
	$(call cargo_test,$(SPIFFE_RUSTLS_MANIFEST),--no-default-features --features ring,tracing)
	$(call cargo_test,$(SPIFFE_RUSTLS_MANIFEST),--no-default-features --features ring,logging,parking-lot)

# -----------------------------------------------------------------------------
# Examples
# -----------------------------------------------------------------------------

examples:
	$(info ==> Build examples)
	$(call cargo_build,$(SPIFFE_RUSTLS_MANIFEST),--examples)

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
