.PHONY: help fmt fmt-check clippy test build clean gen gen-spiffe gen-spire-api ci \
        build-all test-all clippy-all

help:
	@echo "Targets:"
	@echo "  make fmt           Format (stable)"
	@echo "  make clippy        Clippy (default workspace)"
	@echo "  make test          Test (default workspace)"
	@echo "  make build         Build (default workspace)"
	@echo "  make clippy-all    Clippy: workspace + spiffe-rustls (ring + aws-lc-rs)"
	@echo "  make test-all      Test: workspace + spiffe-rustls (ring + aws-lc-rs)"
	@echo "  make build-all     Build: workspace + spiffe-rustls (ring + aws-lc-rs)"
	@echo "  make gen           Generate all codegen"

fmt:
	cargo fmt

clippy:
	cargo clippy --workspace --all-targets -- -D warnings

test:
	cargo test --workspace

build:
	cargo build --workspace

clippy-all: clippy
	cargo clippy -p spiffe-rustls --all-targets --no-default-features --features ring -- -D warnings
	cargo clippy -p spiffe-rustls --all-targets --no-default-features --features aws-lc-rs -- -D warnings

test-all: test
	cargo test -p spiffe-rustls --all-targets --no-default-features --features ring
	cargo test -p spiffe-rustls --all-targets --no-default-features --features aws-lc-rs

build-all: build
	cargo build -p spiffe-rustls --all-targets --no-default-features --features ring
	cargo build -p spiffe-rustls --all-targets --no-default-features --features aws-lc-rs

clean:
	cargo clean

gen: gen-spiffe gen-spire-api

gen-spiffe:
	cargo run -p xtask -- gen spiffe

gen-spire-api:
	cargo run -p xtask -- gen spire-api
