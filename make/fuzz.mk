FUZZ_DIR := spiffe/fuzz
FUZZ_TARGETS := \
	fuzz_spiffe_id_parse \
	fuzz_trust_domain_parse \
	fuzz_x509_svid_parse \
	fuzz_jwt_and_jwks_parse

# Default fuzzing duration (seconds).
# Keep this short to preserve fast developer feedback.
#
# Override for deeper fuzzing:
#   FUZZ_SECONDS=300 make fuzz
#   FUZZ_SECONDS=1800 make fuzz
FUZZ_SECONDS ?= 60
FUZZ_MAX_LEN ?= 2048
FUZZ_DICT ?= fuzz.dict

# Nightly toolchain for every fuzz recipe.
# CI exports a pinned nightly such as nightly-2026-10-01.
# Local runs default to the rolling nightly channel.
FUZZ_TOOLCHAIN ?= nightly

# Cargo triple passed to cargo-fuzz with --target.
# Leave unset to use the fuzz toolchain's host triple. That keeps macOS on
# Darwin and glibc Linux on the matching linux-gnu triple.
#
# cargo-fuzz otherwise defaults to the triple it was compiled for. Its Linux
# release binary is x86_64-unknown-linux-musl, and AddressSanitizer cannot
# link musl's statically linked libc.
FUZZ_TARGET ?=

# Shell fragment that sets `toolchain` and `target`.
# Expand it in one backslash-continued recipe after `set -euo pipefail`.
FUZZ_RESOLVE = \
	toolchain='$(FUZZ_TOOLCHAIN)'; \
	if [ -n '$(FUZZ_TARGET)' ]; then \
		target='$(FUZZ_TARGET)'; \
	elif ! target="$$(rustc "+$${toolchain}" --print host-tuple 2>/dev/null)"; then \
		target="$$(rustc "+$${toolchain}" -vV | awk '/^host: / { print $$2 }')"; \
	fi; \
	case "$${target}" in \
		*-linux-musl*) \
			printf '%s\n' "error: AddressSanitizer cannot link musl target '$${target}' (libc is statically linked)." >&2; \
			printf '%s\n' "error: set FUZZ_TARGET to the matching linux-gnu triple (CI uses x86_64-unknown-linux-gnu)." >&2; \
			exit 1 ;; \
		'') \
			printf '%s\n' "error: failed to resolve a fuzz target triple for toolchain '$${toolchain}'." >&2; \
			exit 1 ;; \
	esac; \
	printf '%s\n' "==> fuzz toolchain $${toolchain}"; \
	printf '%s\n' "==> fuzz target $${target}"; \
	rustc "+$${toolchain}" -vV | awk '/^(release|host): /'

.PHONY: fuzz-setup fuzz-build
fuzz-setup:
	@command -v cargo-fuzz >/dev/null 2>&1 || cargo '+$(FUZZ_TOOLCHAIN)' install cargo-fuzz --locked

fuzz-build: fuzz-setup
	@set -euo pipefail; \
	$(FUZZ_RESOLVE); \
	cd '$(FUZZ_DIR)'; \
	for t in $(FUZZ_TARGETS); do \
		printf '%s\n' "==> build fuzz target $${t}"; \
		cargo "+$${toolchain}" fuzz build "$${t}" --target "$${target}"; \
	done

.PHONY: fuzz
fuzz: fuzz-setup
	@set -euo pipefail; \
	$(FUZZ_RESOLVE); \
	cd '$(FUZZ_DIR)'; \
	for t in $(FUZZ_TARGETS); do \
		printf '%s\n' "==> fuzz $${t} ($(FUZZ_SECONDS)s, max_len=$(FUZZ_MAX_LEN), dict=$(FUZZ_DICT))"; \
		cargo "+$${toolchain}" fuzz run "$${t}" --target "$${target}" -- \
			-max_total_time=$(FUZZ_SECONDS) \
			-max_len=$(FUZZ_MAX_LEN) \
			-dict=$(FUZZ_DICT); \
	done
