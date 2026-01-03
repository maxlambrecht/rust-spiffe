CARGO ?= cargo

# -----------------------------------------------------------------------------
# Policy
# -----------------------------------------------------------------------------

MSRV ?= 1.85.0

SPIFFE_MANIFEST        := spiffe/Cargo.toml
SPIFFE_RUSTLS_MANIFEST := spiffe-rustls/Cargo.toml
SPIRE_API_MANIFEST     := spire-api/Cargo.toml

.PHONY: help fmt fmt-check clean all full msrv integration-tests spiffe spire-api spiffe-rustls

help:
	@echo "Targets:"
	@echo "  make all               Run all crate checks (spiffe, spire-api, spiffe-rustls)"
	@echo "  make full              all + integration-tests"
	@echo "  make msrv              Verify MSRV ($(MSRV)) across key lanes"
	@echo "  make integration-tests Run integration tests"
	@echo "  make spiffe            Clippy/build/test across spiffe feature lanes"
	@echo "  make spire-api         Clippy/build/test"
	@echo "  make spiffe-rustls     Clippy/build/test (default + aws-lc-rs + tracing lane)"
	@echo "  make fmt | fmt-check   rustfmt"
	@echo "  make clean             cargo clean"

# -----------------------------------------------------------------------------
# Helpers
# -----------------------------------------------------------------------------

# $(call cargo_cmd,<subcommand>,<manifest>,<extra args>)
define cargo_cmd
	$(CARGO) $(1) --manifest-path $(2) --all-targets $(3)
endef

# $(call cargo_cmd_deny_warnings,<subcommand>,<manifest>,<extra args>)
define cargo_cmd_deny_warnings
	$(CARGO) $(1) --manifest-path $(2) --all-targets $(3) -- -D warnings
endef

# MSRV variants (use cargo +<toolchain>)
# $(call msrv_cmd,<subcommand>,<manifest>,<extra args>)
define msrv_cmd
	cargo +$(MSRV) $(1) --manifest-path $(2) --all-targets $(3)
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
# MSRV policy check
# -----------------------------------------------------------------------------
# Keep MSRV lanes limited but representative of the major feature surfaces.

msrv:
	$(info ==> MSRV policy check: Rust $(MSRV))
	cargo +$(MSRV) --version

	$(info ==> spiffe (MSRV))
	$(call msrv_cmd,test,$(SPIFFE_MANIFEST),)
	$(call msrv_cmd,test,$(SPIFFE_MANIFEST),--no-default-features --features x509)
	$(call msrv_cmd,test,$(SPIFFE_MANIFEST),--no-default-features --features transport)
	$(call msrv_cmd,test,$(SPIFFE_MANIFEST),--no-default-features --features transport-grpc)
	$(call msrv_cmd,test,$(SPIFFE_MANIFEST),--no-default-features --features workload-api)
	$(call msrv_cmd,test,$(SPIFFE_MANIFEST),--no-default-features --features x509-source)
	$(call msrv_cmd,test,$(SPIFFE_MANIFEST),--no-default-features --features jwt)
	$(call msrv_cmd,test,$(SPIFFE_MANIFEST),--no-default-features --features jwt-verify-rust-crypto)
	$(call msrv_cmd,test,$(SPIFFE_MANIFEST),--no-default-features --features jwt-verify-aws-lc-rs)
	$(call msrv_cmd,test,$(SPIFFE_MANIFEST),--no-default-features --features logging)
	$(call msrv_cmd,test,$(SPIFFE_MANIFEST),--no-default-features --features tracing)

	$(info ==> spire-api (MSRV))
	$(call msrv_cmd,test,$(SPIRE_API_MANIFEST),)

	$(info ==> spiffe-rustls (MSRV))
	$(call msrv_cmd,test,$(SPIFFE_RUSTLS_MANIFEST),)
	$(call msrv_cmd,test,$(SPIFFE_RUSTLS_MANIFEST),--no-default-features --features aws-lc-rs)
	$(call msrv_cmd,test,$(SPIFFE_RUSTLS_MANIFEST),--no-default-features --features ring,tracing)

# -----------------------------------------------------------------------------
# Integration tests (SPIRE)
# -----------------------------------------------------------------------------

integration-tests:
	$(info ==> Run integration tests)
	$(CARGO) test --manifest-path $(SPIFFE_RUSTLS_MANIFEST) -- --ignored
	$(CARGO) test --manifest-path $(SPIFFE_MANIFEST) --features x509-source,jwt -- --ignored
	$(CARGO) test --manifest-path $(SPIRE_API_MANIFEST) --features integration-tests

# -----------------------------------------------------------------------------
# spiffe
# -----------------------------------------------------------------------------
# Feature lanes (single-feature coverage):
# - x509
# - transport
# - transport-grpc
# - workload-api-core
# - workload-api-x509
# - workload-api-jwt
# - workload-api-full
# - x509-source
# - jwt
# - jwt-verify-rust-crypto
# - jwt-verify-aws-lc-rs
# - logging
# - tracing
#
# Plus a few “combo lanes” that catch integration issues around observability
# and JWT verification backends.

spiffe:
	$(info ==> spiffe: clippy (feature lanes))
	$(call cargo_cmd_deny_warnings,clippy,$(SPIFFE_MANIFEST),)
	$(call cargo_cmd_deny_warnings,clippy,$(SPIFFE_MANIFEST),--no-default-features --features x509)
	$(call cargo_cmd_deny_warnings,clippy,$(SPIFFE_MANIFEST),--no-default-features --features transport)
	$(call cargo_cmd_deny_warnings,clippy,$(SPIFFE_MANIFEST),--no-default-features --features transport-grpc)
	$(call cargo_cmd_deny_warnings,clippy,$(SPIFFE_MANIFEST),--no-default-features --features workload-api-core)
	$(call cargo_cmd_deny_warnings,clippy,$(SPIFFE_MANIFEST),--no-default-features --features workload-api-x509)
	$(call cargo_cmd_deny_warnings,clippy,$(SPIFFE_MANIFEST),--no-default-features --features workload-api-jwt)
	$(call cargo_cmd_deny_warnings,clippy,$(SPIFFE_MANIFEST),--no-default-features --features workload-api)
	$(call cargo_cmd_deny_warnings,clippy,$(SPIFFE_MANIFEST),--no-default-features --features workload-api-full)
	$(call cargo_cmd_deny_warnings,clippy,$(SPIFFE_MANIFEST),--no-default-features --features x509-source)
	$(call cargo_cmd_deny_warnings,clippy,$(SPIFFE_MANIFEST),--no-default-features --features jwt)
	$(call cargo_cmd_deny_warnings,clippy,$(SPIFFE_MANIFEST),--no-default-features --features jwt-verify-rust-crypto)
	$(call cargo_cmd_deny_warnings,clippy,$(SPIFFE_MANIFEST),--no-default-features --features jwt-verify-aws-lc-rs)
	$(call cargo_cmd_deny_warnings,clippy,$(SPIFFE_MANIFEST),--no-default-features --features logging)
	$(call cargo_cmd_deny_warnings,clippy,$(SPIFFE_MANIFEST),--no-default-features --features tracing)

	$(call cargo_cmd_deny_warnings,clippy,$(SPIFFE_MANIFEST),--no-default-features --features workload-api-full,logging)
	$(call cargo_cmd_deny_warnings,clippy,$(SPIFFE_MANIFEST),--no-default-features --features workload-api-full,tracing)
	$(call cargo_cmd_deny_warnings,clippy,$(SPIFFE_MANIFEST),--no-default-features --features workload-api-full,tracing,jwt-verify-rust-crypto)
	$(call cargo_cmd_deny_warnings,clippy,$(SPIFFE_MANIFEST),--no-default-features --features workload-api-full,tracing,jwt-verify-aws-lc-rs)

	$(info ==> spiffe: build (feature lanes))
	$(call cargo_cmd,build,$(SPIFFE_MANIFEST),)
	$(call cargo_cmd,build,$(SPIFFE_MANIFEST),--no-default-features --features x509)
	$(call cargo_cmd,build,$(SPIFFE_MANIFEST),--no-default-features --features transport)
	$(call cargo_cmd,build,$(SPIFFE_MANIFEST),--no-default-features --features transport-grpc)
	$(call cargo_cmd,build,$(SPIFFE_MANIFEST),--no-default-features --features workload-api-core)
	$(call cargo_cmd,build,$(SPIFFE_MANIFEST),--no-default-features --features workload-api-x509)
	$(call cargo_cmd,build,$(SPIFFE_MANIFEST),--no-default-features --features workload-api-jwt)
	$(call cargo_cmd,build,$(SPIFFE_MANIFEST),--no-default-features --features workload-api)
	$(call cargo_cmd,build,$(SPIFFE_MANIFEST),--no-default-features --features workload-api-full)
	$(call cargo_cmd,build,$(SPIFFE_MANIFEST),--no-default-features --features x509-source)
	$(call cargo_cmd,build,$(SPIFFE_MANIFEST),--no-default-features --features jwt)
	$(call cargo_cmd,build,$(SPIFFE_MANIFEST),--no-default-features --features jwt-verify-rust-crypto)
	$(call cargo_cmd,build,$(SPIFFE_MANIFEST),--no-default-features --features jwt-verify-aws-lc-rs)
	$(call cargo_cmd,build,$(SPIFFE_MANIFEST),--no-default-features --features logging)
	$(call cargo_cmd,build,$(SPIFFE_MANIFEST),--no-default-features --features tracing)

	$(call cargo_cmd,build,$(SPIFFE_MANIFEST),--no-default-features --features workload-api-full,logging)
	$(call cargo_cmd,build,$(SPIFFE_MANIFEST),--no-default-features --features workload-api-full,tracing)
	$(call cargo_cmd,build,$(SPIFFE_MANIFEST),--no-default-features --features workload-api-full,tracing,jwt-verify-rust-crypto)
	$(call cargo_cmd,build,$(SPIFFE_MANIFEST),--no-default-features --features workload-api-full,tracing,jwt-verify-aws-lc-rs)

	$(info ==> spiffe: test (feature lanes))
	$(call cargo_cmd,test,$(SPIFFE_MANIFEST),)
	$(call cargo_cmd,test,$(SPIFFE_MANIFEST),--no-default-features --features x509)
	$(call cargo_cmd,test,$(SPIFFE_MANIFEST),--no-default-features --features transport)
	$(call cargo_cmd,test,$(SPIFFE_MANIFEST),--no-default-features --features transport-grpc)
	$(call cargo_cmd,test,$(SPIFFE_MANIFEST),--no-default-features --features workload-api-core)
	$(call cargo_cmd,test,$(SPIFFE_MANIFEST),--no-default-features --features workload-api-x509)
	$(call cargo_cmd,test,$(SPIFFE_MANIFEST),--no-default-features --features workload-api-jwt)
	$(call cargo_cmd,test,$(SPIFFE_MANIFEST),--no-default-features --features workload-api-full)
	$(call cargo_cmd,test,$(SPIFFE_MANIFEST),--no-default-features --features x509-source)
	$(call cargo_cmd,test,$(SPIFFE_MANIFEST),--no-default-features --features jwt)
	$(call cargo_cmd,test,$(SPIFFE_MANIFEST),--no-default-features --features jwt-verify-rust-crypto)
	$(call cargo_cmd,test,$(SPIFFE_MANIFEST),--no-default-features --features jwt-verify-aws-lc-rs)
	$(call cargo_cmd,test,$(SPIFFE_MANIFEST),--no-default-features --features logging)
	$(call cargo_cmd,test,$(SPIFFE_MANIFEST),--no-default-features --features tracing)

	$(call cargo_cmd,test,$(SPIFFE_MANIFEST),--no-default-features --features workload-api-full,logging)
	$(call cargo_cmd,test,$(SPIFFE_MANIFEST),--no-default-features --features workload-api-full,tracing)
	$(call cargo_cmd,test,$(SPIFFE_MANIFEST),--no-default-features --features workload-api-full,tracing,jwt-verify-rust-crypto)
	$(call cargo_cmd,test,$(SPIFFE_MANIFEST),--no-default-features --features workload-api-full,tracing,jwt-verify-aws-lc-rs)

# -----------------------------------------------------------------------------
# spire-api
# -----------------------------------------------------------------------------

spire-api:
	$(info ==> spire-api: clippy)
	$(call cargo_cmd_deny_warnings,clippy,$(SPIRE_API_MANIFEST),)

	$(info ==> spire-api: build)
	$(call cargo_cmd,build,$(SPIRE_API_MANIFEST),)

	$(info ==> spire-api: test)
	$(call cargo_cmd,test,$(SPIRE_API_MANIFEST),)

# -----------------------------------------------------------------------------
# spiffe-rustls
# -----------------------------------------------------------------------------

spiffe-rustls:
	$(info ==> spiffe-rustls: clippy)
	$(call cargo_cmd_deny_warnings,clippy,$(SPIFFE_RUSTLS_MANIFEST),)
	$(call cargo_cmd_deny_warnings,clippy,$(SPIFFE_RUSTLS_MANIFEST),--no-default-features --features aws-lc-rs)
	$(call cargo_cmd_deny_warnings,clippy,$(SPIFFE_RUSTLS_MANIFEST),--no-default-features --features ring,tracing)
	$(call cargo_cmd_deny_warnings,clippy,$(SPIFFE_RUSTLS_MANIFEST),--no-default-features --features ring,logging)

	$(info ==> spiffe-rustls: build)
	$(call cargo_cmd,build,$(SPIFFE_RUSTLS_MANIFEST),)
	$(call cargo_cmd,build,$(SPIFFE_RUSTLS_MANIFEST),--no-default-features --features aws-lc-rs)
	$(call cargo_cmd,build,$(SPIFFE_RUSTLS_MANIFEST),--no-default-features --features ring,tracing)
	$(call cargo_cmd,build,$(SPIFFE_RUSTLS_MANIFEST),--no-default-features --features ring,logging)

	$(info ==> spiffe-rustls: test)
	$(call cargo_cmd,test,$(SPIFFE_RUSTLS_MANIFEST),)
	$(call cargo_cmd,test,$(SPIFFE_RUSTLS_MANIFEST),--no-default-features --features aws-lc-rs)
	$(call cargo_cmd,test,$(SPIFFE_RUSTLS_MANIFEST),--no-default-features --features ring,tracing)
	$(call cargo_cmd,test,$(SPIFFE_RUSTLS_MANIFEST),--no-default-features --features ring,logging)
