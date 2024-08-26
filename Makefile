.PHONY: lint
lint:
	@cargo +nightly fmt --check
	@cargo clippy
