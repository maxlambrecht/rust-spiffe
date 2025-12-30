CARGO ?= cargo

# -----------------------------------------------------------------------------
# Policy
# -----------------------------------------------------------------------------

MSRV ?= 1.85.0

SPIFFE_MANIFEST        := spiffe/Cargo.toml
SPIFFE_RUSTLS_MANIFEST := spiffe-rustls/Cargo.toml
SPIRE_API_MANIFEST     := spire-api/Cargo.toml

JWT_VERIFY_BACKEND ?= jwt-verify-rust-crypto
JWT_VERIFY_TEST_AWS_LC ?= 0

# Trace lane (compile/test the `tracing` feature explicitly)
SPIFFE_TRACE_FEATURES := workload-api,tracing

.PHONY: help fmt fmt-check clean all msrv integration-tests spiffe spire-api spiffe-rustls

help:
	@echo "Targets:"
	@echo "  make all               Run all crate checks (spiffe, spire-api, spiffe-rustls)"
	@echo "  make msrv              Verify Minimum Supported Rust Version ($(MSRV))"
	@echo "  make integration-tests Run integration tests"
	@echo "  make spiffe            Clippy/build/test across feature matrix"
	@echo "  make spire-api         Clippy/build/test"
	@echo "  make spiffe-rustls     Clippy/build/test (ring default + aws-lc-rs)"
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

full: all integration-tests

all: fmt-check spiffe spire-api spiffe-rustls
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

msrv:
	@printf "\n==> MSRV policy check: Rust $(MSRV)\n"
	cargo +$(MSRV) --version

	@printf "\n==> spiffe (MSRV)\n"
	$(call msrv_cmd,test,$(SPIFFE_MANIFEST),)
	$(call msrv_cmd,test,$(SPIFFE_MANIFEST),--no-default-features --features transport)
	$(call msrv_cmd,test,$(SPIFFE_MANIFEST),--no-default-features --features $(JWT_VERIFY_BACKEND))
	$(call msrv_cmd,test,$(SPIFFE_MANIFEST),--no-default-features --features workload-api,logging,$(JWT_VERIFY_BACKEND))

	# Tracing-only (no logging fallback)
	$(call msrv_cmd,test,$(SPIFFE_MANIFEST),--no-default-features --features $(SPIFFE_TRACE_FEATURES))

	# Tracing + JWT verify (tracing takes precedence)
	$(call msrv_cmd,test,$(SPIFFE_MANIFEST),--no-default-features --features workload-api,tracing,$(JWT_VERIFY_BACKEND))

ifneq ($(JWT_VERIFY_TEST_AWS_LC),0)
	$(call msrv_cmd,test,$(SPIFFE_MANIFEST),--no-default-features --features jwt-verify-aws-lc-rs)
	$(call msrv_cmd,test,$(SPIFFE_MANIFEST),--no-default-features --features workload-api,jwt-verify-aws-lc-rs)
endif

	@printf "\n==> spire-api (MSRV)\n"
	$(call msrv_cmd,test,$(SPIRE_API_MANIFEST),)

	@printf "\n==> spiffe-rustls (MSRV)\n"
	$(call msrv_cmd,test,$(SPIFFE_RUSTLS_MANIFEST),)
	$(call msrv_cmd,test,$(SPIFFE_RUSTLS_MANIFEST),--no-default-features --features aws-lc-rs)
	# Ensure `tracing` compiles/runs under MSRV
	$(call msrv_cmd,test,$(SPIFFE_RUSTLS_MANIFEST),--no-default-features --features ring,tracing)

# -----------------------------------------------------------------------------
# Integration tests (SPIRE)
# -----------------------------------------------------------------------------

integration-tests:
	@printf "\n==> Run integration tests\n"
	$(CARGO) test --manifest-path $(SPIFFE_MANIFEST) --features integration-tests
	$(CARGO) test --manifest-path $(SPIRE_API_MANIFEST) --features integration-tests
	$(CARGO) test --manifest-path $(SPIFFE_RUSTLS_MANIFEST) --features integration-tests

# -----------------------------------------------------------------------------
# spiffe
# -----------------------------------------------------------------------------
# Lanes:
# - default (workload-api)
# - transport-only
# - jwt verify backend only
# - workload-api + logging + jwt verify
# - tracing-only
# - workload-api + tracing + jwt verify
# - optional aws-lc-rs jwt verify

spiffe:
	@printf "\n==> spiffe: clippy\n"
	$(call cargo_cmd_deny_warnings,clippy,$(SPIFFE_MANIFEST),)
	$(call cargo_cmd_deny_warnings,clippy,$(SPIFFE_MANIFEST),--no-default-features --features transport)
	$(call cargo_cmd_deny_warnings,clippy,$(SPIFFE_MANIFEST),--no-default-features --features $(JWT_VERIFY_BACKEND))
	$(call cargo_cmd_deny_warnings,clippy,$(SPIFFE_MANIFEST),--no-default-features --features workload-api,logging,$(JWT_VERIFY_BACKEND))
	$(call cargo_cmd_deny_warnings,clippy,$(SPIFFE_MANIFEST),--no-default-features --features $(SPIFFE_TRACE_FEATURES))
	$(call cargo_cmd_deny_warnings,clippy,$(SPIFFE_MANIFEST),--no-default-features --features workload-api,tracing,$(JWT_VERIFY_BACKEND))

ifneq ($(JWT_VERIFY_TEST_AWS_LC),0)
	$(call cargo_cmd_deny_warnings,clippy,$(SPIFFE_MANIFEST),--no-default-features --features jwt-verify-aws-lc-rs)
	$(call cargo_cmd_deny_warnings,clippy,$(SPIFFE_MANIFEST),--no-default-features --features workload-api,jwt-verify-aws-lc-rs)
endif

	@printf "\n==> spiffe: build\n"
	$(call cargo_cmd,build,$(SPIFFE_MANIFEST),)
	$(call cargo_cmd,build,$(SPIFFE_MANIFEST),--no-default-features --features transport)
	$(call cargo_cmd,build,$(SPIFFE_MANIFEST),--no-default-features --features $(JWT_VERIFY_BACKEND))
	$(call cargo_cmd,build,$(SPIFFE_MANIFEST),--no-default-features --features workload-api,$(JWT_VERIFY_BACKEND))
	$(call cargo_cmd,build,$(SPIFFE_MANIFEST),--no-default-features --features $(SPIFFE_TRACE_FEATURES))
	$(call cargo_cmd,build,$(SPIFFE_MANIFEST),--no-default-features --features workload-api,tracing,$(JWT_VERIFY_BACKEND))

ifneq ($(JWT_VERIFY_TEST_AWS_LC),0)
	$(call cargo_cmd,build,$(SPIFFE_MANIFEST),--no-default-features --features jwt-verify-aws-lc-rs)
	$(call cargo_cmd,build,$(SPIFFE_MANIFEST),--no-default-features --features workload-api,jwt-verify-aws-lc-rs)
endif

	@printf "\n==> spiffe: test\n"
	$(call cargo_cmd,test,$(SPIFFE_MANIFEST),)
	$(call cargo_cmd,test,$(SPIFFE_MANIFEST),--no-default-features --features transport)
	$(call cargo_cmd,test,$(SPIFFE_MANIFEST),--no-default-features --features $(JWT_VERIFY_BACKEND))
	$(call cargo_cmd,test,$(SPIFFE_MANIFEST),--no-default-features --features workload-api,$(JWT_VERIFY_BACKEND))
	$(call cargo_cmd,test,$(SPIFFE_MANIFEST),--no-default-features --features $(SPIFFE_TRACE_FEATURES))
	$(call cargo_cmd,test,$(SPIFFE_MANIFEST),--no-default-features --features workload-api,tracing,$(JWT_VERIFY_BACKEND))

ifneq ($(JWT_VERIFY_TEST_AWS_LC),0)
	$(call cargo_cmd,test,$(SPIFFE_MANIFEST),--no-default-features --features jwt-verify-aws-lc-rs)
	$(call cargo_cmd,test,$(SPIFFE_MANIFEST),--no-default-features --features workload-api,jwt-verify-aws-lc-rs)
endif

# -----------------------------------------------------------------------------
# spire-api
# -----------------------------------------------------------------------------

spire-api:
	@printf "\n==> spire-api: clippy\n"
	$(call cargo_cmd_deny_warnings,clippy,$(SPIRE_API_MANIFEST),)

	@printf "\n==> spire-api: build\n"
	$(call cargo_cmd,build,$(SPIRE_API_MANIFEST),)

	@printf "\n==> spire-api: test\n"
	$(call cargo_cmd,test,$(SPIRE_API_MANIFEST),)

# -----------------------------------------------------------------------------
# spiffe-rustls
# -----------------------------------------------------------------------------
# Lanes:
# - default (ring)
# - aws-lc-rs
# - integration tests both backends when FAST!=1
# - exercise observability lanes under integration tests when FAST!=1

spiffe-rustls:
	@printf "\n==> spiffe-rustls: clippy\n"
	$(call cargo_cmd_deny_warnings,clippy,$(SPIFFE_RUSTLS_MANIFEST),)
	$(call cargo_cmd_deny_warnings,clippy,$(SPIFFE_RUSTLS_MANIFEST),--no-default-features --features aws-lc-rs)

	@printf "\n==> spiffe-rustls: build\n"
	$(call cargo_cmd,build,$(SPIFFE_RUSTLS_MANIFEST),)
	$(call cargo_cmd,build,$(SPIFFE_RUSTLS_MANIFEST),--no-default-features --features aws-lc-rs)

	@printf "\n==> spiffe-rustls: test\n"
	$(call cargo_cmd,test,$(SPIFFE_RUSTLS_MANIFEST),)
	$(call cargo_cmd,test,$(SPIFFE_RUSTLS_MANIFEST),--no-default-features --features aws-lc-rs)
