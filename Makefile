CARGO ?= cargo
FAST  ?= 0

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

.PHONY: help fmt fmt-check clean all msrv integration-tests spiffe spiffe-rustls spire-api

help:
	@echo "Targets:"
	@echo "  make all               Run all crate checks (spiffe, spire-api, spiffe-rustls)"
	@echo "  make msrv              Verify Minimum Supported Rust Version ($(MSRV))"
	@echo "  make integration-tests Run integration tests"
	@echo "  make spiffe            Clippy/build/test across feature matrix"
	@echo "  make spire-api         Clippy/build/test (plus integration-tests unless FAST=1)"
	@echo "  make spiffe-rustls     Clippy/build/test (ring default + aws-lc-rs)"
	@echo "  make fmt | fmt-check   rustfmt"
	@echo "  make clean             cargo clean"
	@echo ""
	@echo "Env:"
	@echo "  FAST=1                 Skip heavier scenarios (integration-tests, etc.)"
	@echo "  MSRV=1.xx.y            Override MSRV for local checks"
	@echo "  JWT_VERIFY_BACKEND=... Override jwt verify backend feature (default: $(JWT_VERIFY_BACKEND))"
	@echo "  JWT_VERIFY_TEST_AWS_LC=1 Enable aws-lc-rs jwt verify backend tests"

# -----------------------------------------------------------------------------
# Global targets
# -----------------------------------------------------------------------------

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
	cargo +$(MSRV) test --manifest-path $(SPIFFE_MANIFEST) --all-targets
	cargo +$(MSRV) test --manifest-path $(SPIFFE_MANIFEST) --all-targets --no-default-features --features transport
	cargo +$(MSRV) test --manifest-path $(SPIFFE_MANIFEST) --all-targets --no-default-features --features $(JWT_VERIFY_BACKEND)
	cargo +$(MSRV) test --manifest-path $(SPIFFE_MANIFEST) --all-targets --no-default-features --features workload-api,$(JWT_VERIFY_BACKEND)

	# Explicit tracing lane (compile/test tracing-only code paths)
	cargo +$(MSRV) test --manifest-path $(SPIFFE_MANIFEST) --all-targets --no-default-features --features $(SPIFFE_TRACE_FEATURES)

ifneq ($(JWT_VERIFY_TEST_AWS_LC),0)
	cargo +$(MSRV) test --manifest-path $(SPIFFE_MANIFEST) --all-targets --no-default-features --features jwt-verify-aws-lc-rs
	cargo +$(MSRV) test --manifest-path $(SPIFFE_MANIFEST) --all-targets --no-default-features --features workload-api,jwt-verify-aws-lc-rs
endif

	@printf "\n==> spire-api (MSRV)\n"
	cargo +$(MSRV) test --manifest-path $(SPIRE_API_MANIFEST) --all-targets

	@printf "\n==> spiffe-rustls (MSRV)\n"
	cargo +$(MSRV) test --manifest-path $(SPIFFE_RUSTLS_MANIFEST) --all-targets
	cargo +$(MSRV) test --manifest-path $(SPIFFE_RUSTLS_MANIFEST) --all-targets --no-default-features --features aws-lc-rs

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

spiffe:
	@printf "\n==> spiffe: clippy\n"
	$(CARGO) clippy --manifest-path $(SPIFFE_MANIFEST) --all-targets -- -D warnings
	$(CARGO) clippy --manifest-path $(SPIFFE_MANIFEST) --all-targets --no-default-features --features transport -- -D warnings
	$(CARGO) clippy --manifest-path $(SPIFFE_MANIFEST) --all-targets --no-default-features --features $(JWT_VERIFY_BACKEND) -- -D warnings
	$(CARGO) clippy --manifest-path $(SPIFFE_MANIFEST) --all-targets --no-default-features --features workload-api,$(JWT_VERIFY_BACKEND) -- -D warnings

	# Explicit tracing lane (compile/check tracing-only code paths)
	$(CARGO) clippy --manifest-path $(SPIFFE_MANIFEST) --all-targets --no-default-features --features $(SPIFFE_TRACE_FEATURES) -- -D warnings

ifneq ($(JWT_VERIFY_TEST_AWS_LC),0)
	$(CARGO) clippy --manifest-path $(SPIFFE_MANIFEST) --all-targets --no-default-features --features jwt-verify-aws-lc-rs -- -D warnings
	$(CARGO) clippy --manifest-path $(SPIFFE_MANIFEST) --all-targets --no-default-features --features workload-api,jwt-verify-aws-lc-rs -- -D warnings
endif

ifneq ($(FAST),1)
	$(CARGO) clippy --manifest-path $(SPIFFE_MANIFEST) --all-targets --no-default-features --features workload-api,integration-tests -- -D warnings
endif

	@printf "\n==> spiffe: build\n"
	$(CARGO) build --manifest-path $(SPIFFE_MANIFEST) --all-targets
	$(CARGO) build --manifest-path $(SPIFFE_MANIFEST) --all-targets --no-default-features --features transport
	$(CARGO) build --manifest-path $(SPIFFE_MANIFEST) --all-targets --no-default-features --features $(JWT_VERIFY_BACKEND)
	$(CARGO) build --manifest-path $(SPIFFE_MANIFEST) --all-targets --no-default-features --features workload-api,$(JWT_VERIFY_BACKEND)

	# Explicit tracing lane
	$(CARGO) build --manifest-path $(SPIFFE_MANIFEST) --all-targets --no-default-features --features $(SPIFFE_TRACE_FEATURES)

ifneq ($(JWT_VERIFY_TEST_AWS_LC),0)
	$(CARGO) build --manifest-path $(SPIFFE_MANIFEST) --all-targets --no-default-features --features jwt-verify-aws-lc-rs
	$(CARGO) build --manifest-path $(SPIFFE_MANIFEST) --all-targets --no-default-features --features workload-api,jwt-verify-aws-lc-rs
endif

ifneq ($(FAST),1)
	$(CARGO) build --manifest-path $(SPIFFE_MANIFEST) --all-targets --no-default-features --features workload-api,integration-tests
endif

	@printf "\n==> spiffe: test\n"
	$(CARGO) test --manifest-path $(SPIFFE_MANIFEST) --all-targets
	$(CARGO) test --manifest-path $(SPIFFE_MANIFEST) --all-targets --no-default-features --features transport
	$(CARGO) test --manifest-path $(SPIFFE_MANIFEST) --all-targets --no-default-features --features $(JWT_VERIFY_BACKEND)
	$(CARGO) test --manifest-path $(SPIFFE_MANIFEST) --all-targets --no-default-features --features workload-api,$(JWT_VERIFY_BACKEND)

	# Explicit tracing lane
	$(CARGO) test --manifest-path $(SPIFFE_MANIFEST) --all-targets --no-default-features --features $(SPIFFE_TRACE_FEATURES)

ifneq ($(JWT_VERIFY_TEST_AWS_LC),0)
	$(CARGO) test --manifest-path $(SPIFFE_MANIFEST) --all-targets --no-default-features --features jwt-verify-aws-lc-rs
	$(CARGO) test --manifest-path $(SPIFFE_MANIFEST) --all-targets --no-default-features --features workload-api,jwt-verify-aws-lc-rs
endif

ifneq ($(FAST),1)
	$(CARGO) test --manifest-path $(SPIFFE_MANIFEST) --all-targets --no-default-features --features workload-api,integration-tests
endif

# -----------------------------------------------------------------------------
# spire-api
# -----------------------------------------------------------------------------

spire-api:
	@printf "\n==> spire-api: clippy\n"
	$(CARGO) clippy --manifest-path $(SPIRE_API_MANIFEST) --all-targets -- -D warnings
ifneq ($(FAST),1)
	$(CARGO) clippy --manifest-path $(SPIRE_API_MANIFEST) --all-targets --no-default-features --features integration-tests -- -D warnings
endif

	@printf "\n==> spire-api: build\n"
	$(CARGO) build --manifest-path $(SPIRE_API_MANIFEST) --all-targets
ifneq ($(FAST),1)
	$(CARGO) build --manifest-path $(SPIRE_API_MANIFEST) --all-targets --no-default-features --features integration-tests
endif

	@printf "\n==> spire-api: test\n"
	$(CARGO) test --manifest-path $(SPIRE_API_MANIFEST) --all-targets
ifneq ($(FAST),1)
	$(CARGO) test --manifest-path $(SPIRE_API_MANIFEST) --all-targets --no-default-features --features integration-tests
endif

# -----------------------------------------------------------------------------
# spiffe-rustls
# -----------------------------------------------------------------------------

spiffe-rustls:
	@printf "\n==> spiffe-rustls: clippy\n"
	$(CARGO) clippy --manifest-path $(SPIFFE_RUSTLS_MANIFEST) --all-targets -- -D warnings
	$(CARGO) clippy --manifest-path $(SPIFFE_RUSTLS_MANIFEST) --all-targets --no-default-features --features aws-lc-rs -- -D warnings

ifneq ($(FAST),1)
	$(CARGO) clippy --manifest-path $(SPIFFE_RUSTLS_MANIFEST) --all-targets --no-default-features --features ring,integration-tests -- -D warnings
	$(CARGO) clippy --manifest-path $(SPIFFE_RUSTLS_MANIFEST) --all-targets --no-default-features --features aws-lc-rs,integration-tests -- -D warnings
endif

	@printf "\n==> spiffe-rustls: build\n"
	$(CARGO) build --manifest-path $(SPIFFE_RUSTLS_MANIFEST) --all-targets
	$(CARGO) build --manifest-path $(SPIFFE_RUSTLS_MANIFEST) --all-targets --no-default-features --features aws-lc-rs

ifneq ($(FAST),1)
	$(CARGO) build --manifest-path $(SPIFFE_RUSTLS_MANIFEST) --all-targets --no-default-features --features ring,integration-tests
	$(CARGO) build --manifest-path $(SPIFFE_RUSTLS_MANIFEST) --all-targets --no-default-features --features aws-lc-rs,integration-tests
endif

	@printf "\n==> spiffe-rustls: test\n"
	$(CARGO) test --manifest-path $(SPIFFE_RUSTLS_MANIFEST) --all-targets
	$(CARGO) test --manifest-path $(SPIFFE_RUSTLS_MANIFEST) --all-targets --no-default-features --features aws-lc-rs

ifneq ($(FAST),1)
	$(CARGO) test --manifest-path $(SPIFFE_RUSTLS_MANIFEST) --all-targets --no-default-features --features ring,integration-tests
	$(CARGO) test --manifest-path $(SPIFFE_RUSTLS_MANIFEST) --all-targets --no-default-features --features aws-lc-rs,integration-tests
endif
