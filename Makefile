.PHONY: help fmt fmt-check clippy test build clean gen gen-spiffe gen-spire-api ci \
        build-all test-all clippy-all

help:
	@echo "Targets:"
	@echo "  make fmt           Format (stable)"
	@echo "  make clippy        Clippy (default workspace)"
	@echo "  make test          Test (default workspace)"
	@echo "  make build         Build (default workspace)"
	@echo "  make gen           Generate all codegen"

fmt:
	cargo fmt

clippy:
	cargo clippy --workspace --all-targets -- -D warnings

test:
	cargo test --workspace

build:
	cargo build --workspace

clean:
	cargo clean

gen: gen-spiffe gen-spire-api

gen-spiffe:
	cargo run -p xtask -- gen spiffe

gen-spire-api:
	cargo run -p xtask -- gen spire-api
